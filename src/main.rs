use std::sync::Arc;
use rand::RngCore;
use rfd::FileDialog;
use rusqlite::{params, OptionalExtension};
use slint::{ModelRc, VecModel, Weak};
use rand::rngs::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use dirs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::fs;
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures_util::{StreamExt, SinkExt};
use r2d2_sqlite::SqliteConnectionManager;
use r2d2::Pool;
use serde_derive::{Serialize, Deserialize};
use serde_json;
use tokio::sync::mpsc::{channel, Sender, Receiver};
use winreg::RegKey;
use winreg::enums::*;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use simple_crypt::{encrypt, decrypt};
use hex; // Added for key encoding

static WEBSOCKET_TASK: Lazy<Mutex<Option<tokio::task::JoinHandle<()>>>> = Lazy::new(|| Mutex::new(None));
static ENCRYPTION_KEY: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

slint::include_modules!();

#[derive(Serialize, Deserialize)]
struct WebSocketResponse {
    password: Option<String>,
    username_email: Option<String>,
    preferences: Vec<FieldPreference>,
    error: Option<String>,
}

#[derive(Debug)]
enum UiUpdate {
    AddPasswordSuccess(Vec<PasswordEntry>),
    Error(String),
}

#[derive(Serialize, Deserialize)]
struct FieldPreference {
    selector: String,
    role: String,
}

async fn start_websocket_server(
    conn: Arc<Pool<SqliteConnectionManager>>,
    black_square_window: Weak<BlackSquareWindow>,
    ui_sender: Sender<UiUpdate>,
    user_id: i32,
) {
    let _ = black_square_window;
    let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
    println!("WebSocket server running on ws://127.0.0.1:9001 for user_id: {}", user_id);

    while let Ok((stream, _)) = listener.accept().await {
        let conn_clone = Arc::clone(&conn);
        let ui_sender_clone = ui_sender.clone();
        let user_id = user_id;
        tokio::spawn(async move {
            if let Ok(ws_stream) = accept_async(stream).await {
                let (mut write, mut read) = ws_stream.split();
                while let Some(msg) = read.next().await {
                    match msg {
                        Ok(Message::Text(text)) => {
                            let response = process_websocket_message(&conn_clone, &text, &ui_sender_clone, user_id).await;
                            let json_response = serde_json::to_string(&response).unwrap_or_else(|e| {
                                format!("{{\"error\":\"Serialization error: {}\"}}", e)
                            });
                            if let Err(e) = write.send(Message::Text(json_response.into())).await {
                                eprintln!("Failed to send response: {}", e);
                                break;
                            }
                        }
                        Ok(_) => println!("Received non-text message"),
                        Err(e) => {
                            eprintln!("Error reading WebSocket message: {}", e);
                            break;
                        }
                    }
                }
            }
        });
    }
}

async fn process_websocket_message(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    text: &str,
    ui_sender: &Sender<UiUpdate>,
    user_id: i32,
) -> WebSocketResponse {
    if text.starts_with("PREF:") {
        let parts: Vec<&str> = text[5..].split("|").collect();
        if parts.len() == 3 {
            match save_field_preference(conn, parts[0], parts[1], parts[2]) {
                Ok(()) => WebSocketResponse { password: None, username_email: None, preferences: Vec::new(), error: None },
                Err(e) => WebSocketResponse { password: None, username_email: None, preferences: Vec::new(), error: Some(e.to_string()) },
            }
        } else {
            WebSocketResponse { password: None, username_email: None, preferences: Vec::new(), error: Some("Invalid PREF format".to_string()) }
        }
    } else if text.starts_with("GET_PREFS") {
        let website = &text[10..];
        match get_field_preferences(conn, website) {
            Ok(prefs) => WebSocketResponse { password: None, username_email: None, preferences: prefs, error: None },
            Err(e) => WebSocketResponse { password: None, username_email: None, preferences: Vec::new(), error: Some(e.to_string()) },
        }
    } else if text.starts_with("GET_PASSWORD:") {
        let website = &text[13..];
        match retrieve_password(conn, user_id, website) {
            Ok(password_opt) => WebSocketResponse { password: password_opt, username_email: None, preferences: Vec::new(), error: None },
            Err(e) => WebSocketResponse { password: None, username_email: None, preferences: Vec::new(), error: Some(e.to_string()) },
        }
    } else if text.starts_with("ADD_PASSWORD") {
        let parts: Vec<&str> = text[12..].split("|").collect();
        if parts.len() == 3 {
            match add_password(conn, user_id, parts[0], parts[1], parts[2]) {
                Ok(()) => {
                    let conn_clone = Arc::clone(conn);
                    let ui_sender_clone = ui_sender.clone();
                    tokio::spawn(async move {
                        let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                        let passwords = read_stored_passwords(&conn_clone, user_id, key).await.unwrap_or_default();
                        let _ = ui_sender_clone.send(UiUpdate::AddPasswordSuccess(passwords)).await;
                    });
                    WebSocketResponse { password: Some(parts[2].to_string()), username_email: Some(parts[1].to_string()), preferences: Vec::new(), error: None }
                }
                Err(e) => {
                    let _ = ui_sender.send(UiUpdate::Error(e.to_string())).await;
                    WebSocketResponse { password: None, username_email: None, preferences: Vec::new(), error: Some(e.to_string()) }
                }
            }
        } else {
            let _ = ui_sender.send(UiUpdate::Error("Invalid ADD_PASSWORD format".to_string())).await;
            WebSocketResponse { password: None, username_email: None, preferences: Vec::new(), error: Some("Invalid ADD_PASSWORD format".to_string()) }
        }
    } else {
        match retrieve_password_and_prefs(conn, user_id, text) {
            Ok((password_opt, username_opt, prefs)) => WebSocketResponse { password: password_opt, username_email: username_opt, preferences: prefs, error: None },
            Err(e) => WebSocketResponse { password: None, username_email: None, preferences: Vec::new(), error: Some(e.to_string()) },
        }
    }
}

fn retrieve_password_and_prefs(conn: &Arc<Pool<SqliteConnectionManager>>, user_id: i32, website: &str) -> Result<(Option<String>, Option<String>, Vec<FieldPreference>)> {
    let db_conn = conn.get()?;
    let mut stmt = db_conn.prepare("SELECT password, username_email FROM Passwords WHERE user_id = ?1 AND website = ?2")?;
    let mut rows = stmt.query(params![user_id, website])?;
    let (encrypted_password, username_email) = if let Some(row) = rows.next()? {
        (Some(row.get(0)?), Some(row.get(1)?))
    } else {
        (None, None)
    };
    let key = ENCRYPTION_KEY.lock().unwrap().clone().ok_or_else(|| anyhow!("Encryption key not set"))?;
    let password = encrypted_password.map(|ep: Vec<u8>| decrypt_password(&ep, &key).unwrap_or("Decryption failed".to_string()));
    let prefs = get_field_preferences(conn, website)?;
    Ok((password, username_email, prefs))
}

fn save_field_preference(conn: &Arc<Pool<SqliteConnectionManager>>, website: &str, selector: &str, role: &str) -> Result<()> {
    if role != "Username" && role != "Password" {
        return Err(anyhow!("Invalid role: {}", role));
    }
    let conn = conn.get()?;
    conn.execute(
        "INSERT OR REPLACE INTO FieldPreferences (website, selector, role) VALUES (?1, ?2, ?3)",
        params![website, selector, role],
    )?;
    Ok(())
}

fn get_field_preferences(conn: &Arc<Pool<SqliteConnectionManager>>, website: &str) -> Result<Vec<FieldPreference>> {
    let conn = conn.get()?;
    let mut stmt = conn.prepare("SELECT selector, role FROM FieldPreferences WHERE website = ?1")?;
    let pref_iter = stmt.query_map(params![website], |row| {
        Ok(FieldPreference { selector: row.get(0)?, role: row.get(1)? })
    })?;
    Ok(pref_iter.collect::<Result<_, _>>()?)
}

fn retrieve_password(conn: &Arc<Pool<SqliteConnectionManager>>, user_id: i32, website: &str) -> Result<Option<String>> {
    let conn = conn.get()?;
    let mut stmt = conn.prepare("SELECT password FROM Passwords WHERE user_id = ?1 AND website = ?2")?;
    let mut rows = stmt.query(params![user_id, website])?;
    let row = rows.next()?;
    let encrypted_password = match row {
        Some(r) => Some(r.get::<_, Vec<u8>>(0)?),
        None => None,
    };
    let key = ENCRYPTION_KEY.lock().unwrap().clone().ok_or_else(|| anyhow!("Encryption key not set"))?;
    let password = encrypted_password.map(|ep| decrypt_password(&ep, &key).unwrap_or("Decryption failed".to_string()));
    Ok(password)
}

async fn setup_databases(db_paths: &[&str]) -> Result<Arc<Pool<SqliteConnectionManager>>> {
    hash_all_databases(db_paths).await?;
    let manager = SqliteConnectionManager::file(db_paths[0]); // Initially unencrypted
    let pool = Arc::new(Pool::builder().max_size(15).build(manager)?);

    // Create tables (initially unencrypted; will be rekeyed after first registration)
    {
        let conn = pool.get()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL CHECK(length(password) <= 128),
                salt TEXT NOT NULL,
                hash TEXT NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Passwords (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                website TEXT NOT NULL,
                username_email TEXT NOT NULL,
                password BLOB NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id, website, username_email)
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS FieldPreferences (
                id INTEGER PRIMARY KEY,
                website TEXT NOT NULL,
                selector TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('Username', 'Password')),
                UNIQUE(website, selector)
            )",
            [],
        )?;
    }

    hash_all_databases(db_paths).await?;
    Ok(pool)
}

fn spawn_ui_update_handler(weak_window: Weak<BlackSquareWindow>, mut ui_receiver: Receiver<UiUpdate>) {
    tokio::spawn(async move {
        while let Some(update) = ui_receiver.recv().await {
            let weak = weak_window.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    match update {
                        UiUpdate::AddPasswordSuccess(passwords) => {
                            window.set_message("✅ Password added successfully!".into());
                            window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                        }
                        UiUpdate::Error(msg) => window.set_message(format!("❌ {}", msg).into()),
                    }
                }
            }).expect("Failed to invoke from event loop");
        }
    });
}

fn setup_login_handler(
    ui: &Arc<LoginWindow>,
    conn: &Arc<Pool<SqliteConnectionManager>>,
    black_square_window: &Arc<BlackSquareWindow>,
) {
    let ui_weak = ui.as_weak();
    let conn = Arc::clone(conn);
    let black_weak = black_square_window.as_weak();

    ui.on_login_clicked(move || {
        let ui = ui_weak.upgrade().unwrap();
        let (username, password) = (ui.get_username().to_string(), ui.get_password().to_string());
        if username.is_empty() || password.is_empty() {
            ui.set_message("Please enter a username and password.".into());
            return;
        }

        let conn = Arc::clone(&conn);
        let ui_weak = ui_weak.clone();
        let black_weak = black_weak.clone();

        slint::spawn_local(async move {
            let result = check_login(&conn, &username, &password, ui_weak.clone(), black_weak.clone()).await;
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    match result {
                        Ok((true, user_id)) => {
                            ui.set_message("Login successful!".into());
                            ui.set_username("".into());
                            ui.set_password("".into());
                            ui.hide().unwrap();
                            if let Some(window) = black_weak.upgrade() {
                                let (ui_sender, ui_receiver) = channel::<UiUpdate>(100);
                                let handle = tokio::spawn(start_websocket_server(
                                    Arc::clone(&conn),
                                    window.as_weak(),
                                    ui_sender,
                                    user_id,
                                ));
                                *WEBSOCKET_TASK.lock().unwrap() = Some(handle);
                                spawn_ui_update_handler(window.as_weak(), ui_receiver);
                                setup_password_handlers(&Arc::new(window), &conn, user_id);
                            }
                        }
                        Ok((false, _)) => ui.set_message("Invalid username or password.".into()),
                        Err(e) => ui.set_message(format!("Login error: {}", e).into()),
                    }
                }
            }).unwrap();
        }).unwrap();
    });
}

fn setup_forgot_password_handler(
    ui: &Arc<LoginWindow>,
    conn: &Arc<Pool<SqliteConnectionManager>>,
    black_square_window: &Arc<BlackSquareWindow>,
) {
    let ui_weak = ui.as_weak();
    let conn = Arc::clone(conn);
    let black_weak = black_square_window.as_weak();

    ui.on_forgot_password(move || {
        let ui = ui_weak.upgrade().unwrap();
        let username = ui.get_username().to_string();
        if username.is_empty() {
            ui.set_message("Please enter your username before recovering your password.".into());
            return;
        }

        let conn = Arc::clone(&conn);
        let ui_weak = ui_weak.clone();
        let black_weak = black_weak.clone();

        slint::spawn_local(async move {
            let result = forgot_password(&conn, &username, black_weak).await;
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    match result {
                        Ok(_) => {
                            ui.set_message("Password recovery process started.".into());
                            ui.hide().unwrap();
                        }
                        Err(e) => ui.set_message(format!("Password recovery error: {}", e).into()),
                    }
                }
            }).unwrap();
        }).unwrap();
    });
}

fn setup_password_handlers(
    black_square_window: &Arc<BlackSquareWindow>,
    conn: &Arc<Pool<SqliteConnectionManager>>,
    user_id: i32,
) {
    let black_weak = black_square_window.as_weak();
    let conn = Arc::clone(conn);

    black_square_window.on_savePassword({
        let black_weak = black_weak.clone();
        let conn = Arc::clone(&conn);
        let user_id = user_id;
        move || {
            let window = black_weak.upgrade().unwrap();
            let (website, username_email, password) = (
                window.get_selected_website().to_string(),
                window.get_selected_username_email().to_string(),
                window.get_selected_password().to_string(),
            );
            if website.is_empty() || username_email.is_empty() || password.is_empty() {
                window.set_message("All fields are required.".into());
                return;
            }

            let conn = Arc::clone(&conn);
            let black_weak = black_weak.clone();
            slint::spawn_local(async move {
                let result = if window.get_isAddMode() {
                    add_password(&conn, user_id, &website, &username_email, &password)
                } else {
                    update_password(&conn, window.get_id(), user_id, &website, &username_email, &password).await
                };
                let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                let passwords = read_stored_passwords(&conn, user_id, key).await.unwrap_or_default();
                slint::invoke_from_event_loop(move || {
                    if let Some(window) = black_weak.upgrade() {
                        match result {
                            Ok(_) => {
                                window.set_message(if window.get_isAddMode() { "Password added successfully!" } else { "Password updated successfully!" }.into());
                                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            }
                            Err(e) => window.set_message(format!("Error: {}", e).into()),
                        }
                    }
                }).unwrap();
            }).unwrap();
        }
    });

    black_square_window.on_edit({
        let black_weak = black_weak.clone();
        let conn = Arc::clone(&conn);
        let user_id = user_id;
        move |id, website, username_email, password| {
            let window = black_weak.upgrade().unwrap();
            let (website, username_email, password) = (website.to_string(), username_email.to_string(), password.to_string());
            if website.is_empty() || username_email.is_empty() || password.is_empty() {
                window.set_message("All fields must be filled.".into());
                return;
            }

            let conn = Arc::clone(&conn);
            let black_weak = black_weak.clone();
            slint::spawn_local(async move {
                let result = update_password(&conn, id, user_id, &website, &username_email, &password).await;
                let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                let passwords = read_stored_passwords(&conn, user_id, key).await.unwrap_or_default();
                slint::invoke_from_event_loop(move || {
                    if let Some(window) = black_weak.upgrade() {
                        match result {
                            Ok(_) => {
                                window.set_message("✅ Password updated successfully!".into());
                                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            }
                            Err(e) => window.set_message(format!("❌ Error updating password: {}", e).into()),
                        }
                    }
                }).unwrap();
            }).unwrap();
        }
    });

    black_square_window.on_deletePassword({
        let black_weak = black_weak.clone();
        let conn = Arc::clone(&conn);
        let user_id = user_id;
        move |id| {
            let conn = Arc::clone(&conn);
            let black_weak = black_weak.clone();
            slint::spawn_local(async move {
                let result = delete_password(&conn, id, user_id).await;
                let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                let passwords = read_stored_passwords(&conn, user_id, key).await.unwrap_or_default();
                slint::invoke_from_event_loop(move || {
                    if let Some(window) = black_weak.upgrade() {
                        match result {
                            Ok(_) => {
                                window.set_message("✅ Password deleted successfully!".into());
                                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            }
                            Err(e) => window.set_message(format!("❌ Error deleting password: {}", e).into()),
                        }
                    }
                }).unwrap();
            }).unwrap();
        }
    });

    black_square_window.on_toggle_autostart({
        let black_weak = black_weak.clone();
        move |enabled| {
            let window = black_weak.upgrade().unwrap();
            let app_name = "EZPass";
            let exe_path = std::env::current_exe().unwrap().to_str().unwrap().to_string();
            if enabled {
                if let Err(e) = add_to_startup(app_name, &exe_path) {
                    window.set_message(format!("❌ Failed to enable autostart: {}", e).into());
                } else {
                    window.set_message("✅ Autostart enabled".into());
                }
            } else {
                if let Err(e) = remove_from_startup(app_name) {
                    window.set_message(format!("❌ Failed to disable autostart: {}", e).into());
                } else {
                    window.set_message("✅ Autostart disabled".into());
                }
            }
        }
    });

    black_square_window.on_export_database({
        let black_weak = black_weak.clone();
        move || {
            let window = black_weak.upgrade().unwrap();
            let file_path = FileDialog::new()
                .set_file_name("passwords.db")
                .save_file()
                .ok_or_else(|| anyhow!("User cancelled export"))
                .unwrap();
            if let Err(e) = fs::copy(DB_PATHS[0], &file_path) {
                window.set_message(format!("❌ Export failed: {}", e).into());
            } else {
                window.set_message("✅ Database exported successfully!".into());
            }
        }
    });

    black_square_window.on_import_database({
        let black_weak = black_weak.clone();
        let conn = Arc::clone(&conn);
        let user_id = user_id;
        move || {
            let file_path = FileDialog::new()
                .set_title("Select a database to import")
                .pick_file()
                .ok_or_else(|| anyhow!("User cancelled import"))
                .unwrap();

            let conn = Arc::clone(&conn);
            let black_weak = black_weak.clone();
            slint::spawn_local(async move {
                let result = import_database(&conn, &file_path, user_id, black_weak.clone()).await;
                slint::invoke_from_event_loop(move || {
                    if let Some(window) = black_weak.upgrade() {
                        match result {
                            Ok(_) => window.set_message("✅ Database imported successfully!".into()),
                            Err(e) => window.set_message(format!("❌ Import failed: {}", e).into()),
                        }
                    }
                }).unwrap();
            }).unwrap();
        }
    });
}

fn setup_register_handler(
    ui: &Arc<LoginWindow>,
    conn: &Arc<Pool<SqliteConnectionManager>>,
) {
    let ui_weak = ui.as_weak();
    let conn = Arc::clone(conn);

    ui.on_register_clicked(move || {
        let ui = ui_weak.upgrade().unwrap();
        let (username, password) = (ui.get_username().to_string(), ui.get_password().to_string());
        if username.is_empty() || password.is_empty() {
            ui.set_message("Please enter both username and password.".into());
            return;
        }

        let conn = Arc::clone(&conn);
        let ui_weak = ui_weak.clone();
        slint::spawn_local(async move {
            let result = register_user(conn, username, password).await;
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    match result {
                        Ok(_) => {
                            ui.set_message("Registration successful!".into());
                            ui.set_username("".into());
                            ui.set_password("".into());
                            slint::spawn_local(async move {
                                if hash_all_databases(DB_PATHS.as_slice()).await.is_err() {
                                    eprintln!("Failed to hash databases after registration.");
                                }
                            }).unwrap();
                        }
                        Err(e) => {
                            ui.set_message(match e.to_string() {
                                s if s.contains("UNIQUE constraint failed") => "Username already exists. Please choose another.".into(),
                                s if s.contains("User cancelled file save") => "Registration failed: You must save the master key file.".into(),
                                s => format!("Registration failed: {}", s).into(),
                            });
                        }
                    }
                }
            }).unwrap();
        }).unwrap();
    });
}

async fn check_login(
    conn: &Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
    username: &str,
    password: &str,
    _ui_handle: Weak<LoginWindow>,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<(bool, i32)> {
    let conn_inner = conn.get()?;
    let mut stmt = conn_inner.prepare("SELECT id, password, salt FROM users WHERE username = ?")?;
    let row: Option<(i32, String, String)> = stmt.query_row(params![username], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    }).optional()?;
    
    if let Some((user_id, stored_password, salt)) = row {
        let parsed_hash = PasswordHash::new(&stored_password)
            .map_err(|e| anyhow!("Failed to parse password hash: {}", e))?;
        if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok() {
            let key = derive_key(password, &salt)?;
            let hex_key = hex::encode(&key);
            println!("Setting key (hex): {}", hex_key); // Debug log
            conn_inner.execute(&format!("PRAGMA key = '{}';", hex_key), [])?;
            *ENCRYPTION_KEY.lock().unwrap() = Some(key.clone());
            println!("Encryption key set: {:x?}", key); // Debug log
            let passwords = read_stored_passwords(conn, user_id, key.clone()).await?;
            slint::invoke_from_event_loop(move || {
                if let Some(window) = black_square_window_handle.upgrade() {
                    window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                    window.show().unwrap();
                }
            })?;
            return Ok((true, user_id));
        }
    }
    Ok((false, 0))
}

async fn read_stored_passwords(conn: &Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>, user_id: i32, key: Vec<u8>) -> Result<Vec<PasswordEntry>> {
    let conn = conn.get()?;
    let mut stmt = conn.prepare("SELECT id, website, username_email, password FROM Passwords WHERE user_id = ?1")?;
    let password_iter = stmt.query_map(params![user_id], |row| {
        let id: i32 = row.get(0)?;
        let website: String = row.get(1)?;
        let username_email: String = row.get(2)?;
        let encrypted_password: Vec<u8> = row.get(3)?;
        match decrypt_password(&encrypted_password, &key) {
            Ok(password) => Ok(PasswordEntry {
                id,
                website: website.into(),
                username_email: username_email.into(),
                password: password.into(),
            }),
            Err(e) => {
                println!("Decryption error for password ID {}: {}", id, e); // Debug log
                Ok(PasswordEntry {
                    id,
                    website: website.into(),
                    username_email: username_email.into(),
                    password: format!("Decryption failed: {}", e).into(),
                })
            }
        }
    })?;
    Ok(password_iter.collect::<Result<_, _>>()?)
}

async fn forgot_password(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    username: &str,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<()> {
    let mut dialog = FileDialog::new().set_title("Select your masterkey file");
    if let Some(desktop_dir) = dirs::desktop_dir() {
        dialog = dialog.set_directory(&desktop_dir);
    }

    let file_path = dialog.pick_file().ok_or_else(|| anyhow!("User cancelled file selection"))?;
    let file_hash = fs::read_to_string(&file_path)?;
    let conn = conn.get()?;
    let db_hash: String = conn.query_row("SELECT hash FROM users WHERE username = ?1", params![username], |row| row.get(0))?;

    if file_hash == db_hash {
        slint::invoke_from_event_loop(move || {
            if let Some(window) = black_square_window_handle.upgrade() {
                window.show().unwrap();
            }
        })?;
        Ok(())
    } else {
        Err(anyhow!("Hash mismatch: Unable to recover password"))
    }
}

async fn register_user(conn: Arc<Pool<SqliteConnectionManager>>, username: String, password: String) -> Result<()> {
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = hash_password(&password, &salt)?;
    let random_hash = generate_random_hash()?;
    let key = derive_key(&password, &salt.to_string())?;
    let hex_key = hex::encode(&key);

    let file_path = tokio::task::spawn_blocking(|| {
        FileDialog::new().set_file_name("masterkey.txt").save_file()
    })
    .await?.ok_or_else(|| anyhow!("User cancelled file save"))?;

    export_hash_to_file(&random_hash, &file_path).await?;

    let conn = conn.get()?;
    conn.execute(&format!("PRAGMA rekey = '{}';", hex_key), [])?; // Rekey the database
    conn.execute(
        "INSERT INTO users (username, password, salt, hash) VALUES (?1, ?2, ?3, ?4)",
        params![username, hashed_password, salt.to_string(), random_hash],
    )?;
    *ENCRYPTION_KEY.lock().unwrap() = Some(key);
    Ok(())
}

fn hash_password(password: &str, salt: &SaltString) -> Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), salt)
        .map_err(|e| anyhow!(e))?
        .to_string())
}

fn generate_random_hash() -> Result<String> {
    let mut random_bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut random_bytes);
    let mut hasher = Sha256::default();
    hasher.update(&random_bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

async fn export_hash_to_file(hash: &str, file_path: &PathBuf) -> Result<()> {
    let mut file = File::create(file_path).await?;
    file.write_all(hash.as_bytes()).await?;
    Ok(())
}

async fn hash_database(file_path: &str) -> Result<String> {
    let mut file = File::open(file_path).await?;
    let mut hasher = Sha256::default();
    let mut buffer = [0; 1024];
    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

async fn hash_all_databases(db_paths: &[&str]) -> Result<()> {
    for db_path in db_paths {
        if Path::new(db_path).exists() {
            match hash_database(db_path).await {
                Ok(hash) => println!("{} hash: {}", db_path, hash),
                Err(e) => eprintln!("Failed to hash {}: {}", db_path, e),
            }
        }
    }
    Ok(())
}

fn add_password(conn: &Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>, user_id: i32, website: &str, username_email: &str, password: &str) -> Result<()> {
    let key = ENCRYPTION_KEY.lock().unwrap().clone().ok_or_else(|| anyhow!("Encryption key not set"))?;
    let encrypted_password = encrypt_password(password, &key)?;
    let conn = conn.get()?;
    conn.execute(
        "INSERT INTO Passwords (user_id, website, username_email, password) VALUES (?1, ?2, ?3, ?4)",
        params![user_id, website, username_email, encrypted_password],
    )?;
    println!("Password added for user_id: {}, website: {}", user_id, website); // Debug log
    Ok(())
}

async fn update_password(conn: &Arc<Pool<SqliteConnectionManager>>, id: i32, user_id: i32, website: &str, username_email: &str, password: &str) -> Result<()> {
    let key = ENCRYPTION_KEY.lock().unwrap().clone().ok_or_else(|| anyhow!("Encryption key not set"))?;
    let encrypted_password = encrypt_password(password, &key)?;
    let conn = conn.get()?;
    let rows_affected = conn.execute(
        "UPDATE Passwords SET website = ?1, username_email = ?2, password = ?3 WHERE id = ?4 AND user_id = ?5",
        params![website, username_email, encrypted_password, id, user_id],
    )?;
    if rows_affected == 0 { return Err(anyhow!("No matching record found to update")); }
    Ok(())
}

async fn delete_password(conn: &Arc<Pool<SqliteConnectionManager>>, id: i32, user_id: i32) -> Result<()> {
    let conn = conn.get()?;
    let rows_affected = conn.execute("DELETE FROM Passwords WHERE id = ?1 AND user_id = ?2", params![id, user_id])?;
    if rows_affected == 0 { return Err(anyhow!("No matching record found to delete")); }
    Ok(())
}

fn add_to_startup(app_name: &str, app_path: &str) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey_with_flags("Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_SET_VALUE)?;
    run_key.set_value(app_name, &app_path)?;
    Ok(())
}

fn remove_from_startup(app_name: &str) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey_with_flags("Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_SET_VALUE)?;
    run_key.delete_value(app_name)?;
    Ok(())
}

fn is_in_startup(app_name: &str) -> Result<bool> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")?;
    Ok(run_key.get_value::<String, _>(app_name).is_ok())
}

fn handle_logout(ui: Arc<LoginWindow>, black_square_window: Arc<BlackSquareWindow>) {
    if let Some(handle) = WEBSOCKET_TASK.lock().unwrap().take() {
        handle.abort();
    }
    *ENCRYPTION_KEY.lock().unwrap() = None; // Clear the encryption key
    black_square_window.set_password_entries(ModelRc::new(VecModel::from(vec![])));
    ui.set_message("".into());
    ui.show().unwrap();
    black_square_window.hide().unwrap();
}

fn derive_key(password: &str, salt: &str) -> Result<Vec<u8>> {
    let salt = argon2::password_hash::SaltString::from_b64(salt)
        .map_err(|e| anyhow!("Invalid salt: {}", e))?;
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Password hashing failed: {}", e))?;
    let key = password_hash.hash.ok_or_else(|| anyhow!("No hash output"))?.as_bytes().to_vec();
    Ok(key)
}

fn encrypt_password(plaintext: &str, key: &[u8]) -> Result<Vec<u8>> {
    encrypt(plaintext.as_bytes(), key)
        .map_err(|e| anyhow!("Encryption failed: {}", e))
}

fn decrypt_password(encrypted_data: &[u8], key: &[u8]) -> Result<String> {
    let plaintext = decrypt(encrypted_data, key)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;
    String::from_utf8(plaintext)
        .map_err(|e| anyhow!("Invalid UTF-8 in decrypted data: {}", e))
}

async fn import_database(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    file_path: &PathBuf,
    current_user_id: i32,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<()> {
    let imported_pool = Pool::builder().max_size(1).build(SqliteConnectionManager::file(file_path))?;
    let imported_conn = imported_pool.get()?;
    
    let mut stmt = imported_conn.prepare("SELECT username, password, salt FROM users LIMIT 1")?;
    let (username, stored_password, salt): (String, String, String) = stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;

    let dialog = FileDialog::new().set_title(&format!("Enter master password for user '{}'", username));
    let master_password = dialog
        .pick_file()
        .map(|_| "Temporary workaround: Assuming password entered via UI".to_string())
        .unwrap_or("".to_string()); // Placeholder; real app needs proper password input

    let parsed_hash = PasswordHash::new(&stored_password).map_err(|e| anyhow!("Failed to parse password hash: {}", e))?;
    if Argon2::default().verify_password(master_password.as_bytes(), &parsed_hash).is_ok() {
        let key = derive_key(&master_password, &salt)?;
        let hex_key = hex::encode(&key);
        imported_conn.execute(&format!("PRAGMA key = '{}';", hex_key), [])?;
        *ENCRYPTION_KEY.lock().unwrap() = Some(key);

        let mut stmt = imported_conn.prepare("SELECT user_id, website, username_email, password FROM Passwords")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;

        let current_conn = conn.get()?;
        for row in rows {
            let (_user_id, website, username_email, encrypted_password): (i32, String, String, Vec<u8>) = row?;
            current_conn.execute(
                "INSERT OR IGNORE INTO Passwords (user_id, website, username_email, password) VALUES (?1, ?2, ?3, ?4)",
                params![current_user_id, website, username_email, encrypted_password],
            )?;
        }

        let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
        let passwords = read_stored_passwords(conn, current_user_id, key).await?;
        slint::invoke_from_event_loop(move || {
            if let Some(window) = black_square_window_handle.upgrade() {
                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
            }
        })?;
        Ok(())
    } else {
        Err(anyhow!("Incorrect master password for imported database"))
    }
}

static DB_PATHS: [&str; 1] = ["app.db"];

#[tokio::main]
async fn main() -> Result<()> {
    let conn = setup_databases(DB_PATHS.as_slice()).await?;

    let ui = Arc::new(LoginWindow::new()?);
    let black_square_window = Arc::new(BlackSquareWindow::new()?);

    let ui_clone = Arc::clone(&ui);
    let black_clone = Arc::clone(&black_square_window);

    black_square_window.on_logout({
        let ui_clone = ui_clone.clone();
        let black_clone = black_clone.clone();
        move || {
            handle_logout(ui_clone.clone(), black_clone.clone());
        }
    });

    setup_login_handler(&ui, &conn, &black_square_window);
    setup_forgot_password_handler(&ui, &conn, &black_square_window);
    setup_register_handler(&ui, &conn);

    let app_name = "EZPass";
    let app_path = std::env::current_exe()?.to_str().ok_or_else(|| anyhow!("Failed to get executable path"))?.to_string();
    if let Ok(is_enabled) = is_in_startup(app_name) {
        black_square_window.set_autostart_enabled(is_enabled);
    } else {
        if let Err(e) = add_to_startup(app_name, &app_path) {
            eprintln!("Failed to add to startup on first run: {}", e);
        } else {
            black_square_window.set_autostart_enabled(true);
            println!("Added EZPass to startup with icon on first run");
        }
    }

    ui.show()?;
    slint::run_event_loop()?;
    Ok(())
}