use std::sync::Arc;
use rfd::FileDialog;
use rusqlite::params;
use slint::{SharedString, ModelRc, VecModel, Weak};
use rand::{rngs::OsRng, Rng};
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
use serde::{Serialize, Deserialize};
use serde_json;


slint::include_modules!();

#[derive(Serialize, Deserialize)]
struct WebSocketResponse {
    password: Option<String>,
    username_email: Option<String>,
    preferences: Vec<FieldPreference>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct FieldPreference {
    selector: String,
    role: String,
}

// WebSocket server
async fn start_websocket_server(conn: Arc<Pool<SqliteConnectionManager>>) {
    let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
    println!("WebSocket server running on ws://127.0.0.1:9001");

    while let Ok((stream, _)) = listener.accept().await {
        let conn_clone = Arc::clone(&conn);
        tokio::spawn(async move {
            match accept_async(stream).await {
                Ok(ws_stream) => {
                    let (mut write, mut read) = ws_stream.split();
                    while let Some(msg) = read.next().await {
                        match msg {
                            Ok(Message::Text(text)) => {
                                let response = if text.starts_with("PREF:") {
                                    let parts: Vec<&str> = text[5..].split("|").collect();
                                    if parts.len() == 3 {
                                        let website = parts[0];
                                        println!("Received ADD_PASSWORD: {}", text);
                                        println!("Parsed parts: {:?}", parts);
                                        let selector = parts[1];
                                        let role = parts[2];
                                        match tokio::task::block_in_place(|| {
                                            save_field_preference(&conn_clone, website, selector, role)
                                        }) {
                                            Ok(()) => WebSocketResponse {
                                                password: None,
                                                username_email: None,
                                                preferences: Vec::new(),
                                                error: None,
                                            },
                                            Err(e) => WebSocketResponse {
                                                password: None,
                                                username_email: None,
                                                preferences: Vec::new(),
                                                error: Some(format!("Failed to save preference: {}", e)),
                                            },
                                        }
                                    } else {
                                        WebSocketResponse {
                                            password: None,
                                            username_email: None,
                                            preferences: Vec::new(),
                                            error: Some("Invalid PREF format".to_string()),
                                        }
                                    }
                                } else if text.starts_with("GET_PREFS") {
                                    let website = &text[10..];
                                    match tokio::task::block_in_place(|| get_field_preferences(&conn_clone, website)) {
                                        Ok(prefs) => WebSocketResponse {
                                            password: None,
                                            username_email: None,
                                            preferences: prefs,
                                            error: None,
                                        },
                                        Err(e) => WebSocketResponse {
                                            password: None,
                                            username_email: None,
                                            preferences: Vec::new(),
                                            error: Some(format!("Failed to get preferences: {}", e)),
                                        },
                                    }
                                } else if text.starts_with("GET_PASSWORD:") {
                                    let website = &text[13..];
                                    match tokio::task::block_in_place(|| retrieve_password(&conn_clone, website)) {
                                        Ok(password_opt) => WebSocketResponse {
                                            password: password_opt,
                                            username_email: None,
                                            preferences: Vec::new(),
                                            error: None,
                                        },
                                        Err(e) => WebSocketResponse {
                                            password: None,
                                            username_email: None,
                                            preferences: Vec::new(),
                                            error: Some(format!("Failed to retrieve password: {}", e)),
                                        },
                                    }
                                } else if text.starts_with("ADD_PASSWORD") {
                                    println!("Received ADD_PASSWORD: {}", text);
                                    let parts: Vec<&str> = text[12..].split("|").collect();
                                    println!("Parsed parts: {:?}", parts); // Add this line
                                    if parts.len() == 3 {
                                        let website = parts[0];
                                        println!("Extracted website: '{}'", website); // Add this line
                                        let username_email = parts[1];
                                        let password = parts[2];
                                        match tokio::task::block_in_place(|| {
                                            add_password(&conn_clone, website, username_email, password)
                                        }) {
                                            Ok(()) => {
                                                println!("Password added successfully for {}", website);
                                                WebSocketResponse {
                                                    password: Some(password.to_string()),
                                                    username_email: Some(username_email.to_string()),
                                                    preferences: Vec::new(),
                                                    error: None,
                                                }
                                            }
                                            Err(e) => {
                                                println!("Failed to add password for {}: {}", website, e);
                                                WebSocketResponse {
                                                    password: None,
                                                    username_email: None,
                                                    preferences: Vec::new(),
                                                    error: Some(format!("Failed to add password: {}", e)),
                                                }
                                            }
                                        }
                                    } else {
                                        println!("Invalid ADD_PASSWORD format: {}", text);
                                        WebSocketResponse {
                                            password: None,
                                            username_email: None,
                                            preferences: Vec::new(),
                                            error: Some("Invalid ADD_PASSWORD format".to_string()),
                                        }
                                    }
                                } else {
                                    println!("Received URL from extension: {}", text);
                                    match tokio::task::block_in_place(|| retrieve_password_and_prefs(&conn_clone, &text)) {
                                        Ok((password_opt, username_opt, prefs)) => WebSocketResponse {
                                            password: password_opt,
                                            username_email: username_opt,
                                            preferences: prefs,
                                            error: None,
                                        },
                                        Err(e) => WebSocketResponse {
                                            password: None,
                                            username_email: None,
                                            preferences: Vec::new(),
                                            error: Some(format!("Database error: {}", e)),
                                        },
                                    }
                                };

                                let json_response = serde_json::to_string(&response).unwrap_or_else(|e| {
                                    format!("{{\"error\":\"Serialization error: {}\"}}", e)
                                });
                                if let Err(e) = write.send(Message::Text(json_response.into())).await {
                                    eprintln!("Failed to send response: {}", e);
                                    break;
                                }
                                println!("Sent response for {}", text);
                            }
                            Ok(message) => {
                                match message {
                                    Message::Binary(data) => println!("Received binary message: {} bytes", data.len()),
                                    Message::Ping(data) => println!("Received ping message: {:?}", data),
                                    Message::Pong(data) => println!("Received pong message: {:?}", data),
                                    Message::Close(close_frame) => println!("Received close message: {:?}", close_frame),
                                    Message::Frame(frame) => println!("Received raw frame: {:?}", frame),
                                    _ => println!("Received unexpected message type"),
                                }
                            }
                            Err(e) => {
                                eprintln!("Error reading WebSocket message: {}", e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => eprintln!("Failed to accept WebSocket connection: {}", e),
            }
        });
    }
}

fn retrieve_password_and_prefs(conn1: &Arc<Pool<SqliteConnectionManager>>, website: &str) -> Result<(Option<String>, Option<String>, Vec<FieldPreference>)> {
    let conn = conn1.get()?;
    let mut stmt = conn.prepare("SELECT password, username_email FROM Passwords WHERE website = ?1")?;
    let mut rows = stmt.query(params![website])?;
    let (password, username_email) = if let Some(row) = rows.next()? {
        (Some(row.get(0)?), Some(row.get(1)?))
    } else {
        (None, None)
    };
    let prefs = get_field_preferences(conn1, website)?;
    Ok((password, username_email, prefs))
}

fn save_field_preference(conn1: &Arc<Pool<SqliteConnectionManager>>, website: &str, selector: &str, role: &str) -> Result<()> {
    if role != "Username" && role != "Password" {
        return Err(anyhow!("Invalid role: {}", role));
    }
    let conn = conn1.get()?;
    conn.execute(
        "INSERT OR REPLACE INTO FieldPreferences (website, selector, role) VALUES (?1, ?2, ?3)",
        params![website, selector, role],
    )?;
    Ok(())
}

fn get_field_preferences(conn1: &Arc<Pool<SqliteConnectionManager>>, website: &str) -> Result<Vec<FieldPreference>> {
    let conn = conn1.get()?;
    let mut stmt = conn.prepare("SELECT selector, role FROM FieldPreferences WHERE website = ?1")?;
    let pref_iter = stmt.query_map(params![website], |row| {
        Ok(FieldPreference {
            selector: row.get(0)?,
            role: row.get(1)?,
        })
    })?;
    let preferences: Vec<_> = pref_iter.collect::<Result<_, _>>()?;
    Ok(preferences)
}

fn retrieve_password(conn1: &Arc<Pool<SqliteConnectionManager>>, website: &str) -> Result<Option<String>> {
    let conn = conn1.get()?;
    let mut stmt = conn.prepare("SELECT password FROM Passwords WHERE website = ?1")?;
    let mut rows = stmt.query(params![website])?;
    if let Some(row) = rows.next()? {
        let password: String = row.get(0)?;
        Ok(Some(password))
    } else {
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let db_paths = vec!["login.db", "pass.db"];
    hash_all_databases(&db_paths).await?;

    let dblogin_path = "login.db";
    let dbpass_path = "pass.db";

    let login_manager = SqliteConnectionManager::file(dblogin_path);
    let pass_manager = SqliteConnectionManager::file(dbpass_path);
    let conn = Arc::new(Pool::builder().max_size(15).build(login_manager)?);
    let conn1 = Arc::new(Pool::builder().max_size(15).build(pass_manager)?);

    {
        let conn = conn.get()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL CHECK(length(password) <= 128),
                hash TEXT NOT NULL
            )",
            [],
        )?;
    }
    {
        let conn1 = conn1.get()?;
        conn1.execute(
            "CREATE TABLE IF NOT EXISTS Passwords (
                id INTEGER PRIMARY KEY,
                website TEXT NOT NULL,
                username_email TEXT NOT NULL,
                password TEXT NOT NULL CHECK(length(password) <= 3128)
            )",
            [],
        )?;
        conn1.execute(
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

    hash_all_databases(&db_paths).await?;

    let ui = Arc::new(LoginWindow::new()?);
    let black_square_window = Arc::new(BlackSquareWindow::new()?);
    let db_paths_for_closure = db_paths.clone(); // First clone for the first closure

    // Login handler
    let ui_handle = ui.as_weak();
    let conn_clone = Arc::clone(&conn);
    let conn1_clone = Arc::clone(&conn1);
    let black_square_window_handle = black_square_window.as_weak();
    ui.on_login_clicked({
        move || {
            let ui = ui_handle.upgrade().unwrap();
            let username = ui.get_username().to_string();
            let password = ui.get_password().to_string();

            if username.is_empty() || password.is_empty() {
                ui.set_message(SharedString::from("Please enter a username and password."));
                return;
            }

            let conn_clone = Arc::clone(&conn_clone);
            let conn1_clone = Arc::clone(&conn1_clone);
            let ui_handle = ui.as_weak();
            let black_square_window_handle = black_square_window_handle.clone();

            slint::spawn_local(async move {
                let result = check_login(
                    &conn_clone,
                    &conn1_clone,
                    &username,
                    &password,
                    ui_handle.clone(),
                    black_square_window_handle.clone(),
                )
                .await;

                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        match result {
                            Ok(true) => {
                                ui.set_message(SharedString::from("Login successful!"));
                                ui.set_username(SharedString::from(""));
                                ui.set_password(SharedString::from(""));
                                ui.hide().unwrap();
                            }
                            Ok(false) => {
                                ui.set_message(SharedString::from("Invalid username or password."));
                            }
                            Err(e) => {
                                ui.set_message(SharedString::from(format!("Login error: {}", e)));
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    // Forgot password handler
    let ui_handle = ui.as_weak();
    let conn_clone = Arc::clone(&conn);
    let black_square_window_handle = black_square_window.as_weak();
    ui.on_forgot_password({
        move || {
            let ui = ui_handle.upgrade().unwrap();
            let username = ui.get_username().to_string();

            if username.is_empty() {
                ui.set_message(SharedString::from(
                    "Please enter your username before recovering your password.",
                ));
                return;
            }

            let conn_clone = Arc::clone(&conn_clone);
            let ui_handle = ui.as_weak();
            let black_square_window_handle = black_square_window_handle.clone();

            slint::spawn_local(async move {
                let username_clone = username.clone();
                let result = forgot_password(&conn_clone, &username_clone, black_square_window_handle.clone()).await;

                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        match result {
                            Ok(_) => {
                                ui.set_message(SharedString::from("Password recovery process started."));
                                ui.hide().unwrap();
                            }
                            Err(e) => {
                                ui.set_message(SharedString::from(format!("Password recovery error: {}", e)));
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    // Save password handler
    let conn1_clone = Arc::clone(&conn1);
    let black_square_window_handle = black_square_window.as_weak();
    black_square_window.on_savePassword({
        move || {
            let window = black_square_window_handle.upgrade().unwrap();
            let website = window.get_selected_website().to_string();
            let username_email = window.get_selected_username_email().to_string();
            let password = window.get_selected_password().to_string();
            if website.is_empty() || username_email.is_empty() || password.is_empty() {
                window.set_message(SharedString::from("All fields are required."));
                return;
            }

            let conn1_clone = Arc::clone(&conn1_clone);
            let window_handle = window.as_weak();

            slint::spawn_local(async move {
                let result = if window.get_isAddMode() {
                    add_password(&conn1_clone, &website, &username_email, &password)
                } else {
                    let id = window.get_id();
                    update_password(&conn1_clone, id, &website, &username_email, &password).await
                };
                let passwords = read_stored_passwords(&conn1_clone).await.unwrap_or_default();

                slint::invoke_from_event_loop(move || {
                    if let Some(window) = window_handle.upgrade() {
                        match result {
                            Ok(_) => {
                                window.set_message(SharedString::from(if window.get_isAddMode() {
                                    "Password added successfully!"
                                } else {
                                    "Password updated successfully!"
                                }));
                                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            }
                            Err(e) => {
                                window.set_message(SharedString::from(format!("Error: {}", e)));
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    // Edit password handler
    let conn1_clone = Arc::clone(&conn1);
    let black_square_window_handle = black_square_window.as_weak();
    black_square_window.on_edit({
        move |id, website, username_email, new_password| {
            let window = black_square_window_handle.upgrade().unwrap();
            let website = website.to_string();
            let username_email = username_email.to_string();
            let new_password = new_password.to_string();

            if website.is_empty() || username_email.is_empty() || new_password.is_empty() {
                window.set_message(SharedString::from("All fields must be filled."));
                return;
            }

            let conn1_clone = Arc::clone(&conn1_clone);
            let window_handle = window.as_weak();

            slint::spawn_local(async move {
                let result = update_password(&conn1_clone, id, &website, &username_email, &new_password).await;
                let passwords = read_stored_passwords(&conn1_clone).await.unwrap_or_default();

                slint::invoke_from_event_loop(move || {
                    if let Some(window) = window_handle.upgrade() {
                        match result {
                            Ok(_) => {
                                window.set_message(SharedString::from("✅ Password updated successfully!"));
                                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            }
                            Err(e) => {
                                window.set_message(SharedString::from(format!("❌ Error updating password: {}", e)));
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    // Delete password handler
    let conn1_clone = Arc::clone(&conn1);
    let black_square_window_handle = black_square_window.as_weak();
    black_square_window.on_deletePassword({
        move |id| {
            let window = black_square_window_handle.upgrade().unwrap();
            let conn1_clone = Arc::clone(&conn1_clone);
            let window_handle = window.as_weak();

            slint::spawn_local(async move {
                let result = delete_password(&conn1_clone, id).await;
                let passwords = read_stored_passwords(&conn1_clone).await.unwrap_or_default();

                slint::invoke_from_event_loop(move || {
                    if let Some(window) = window_handle.upgrade() {
                        match result {
                            Ok(_) => {
                                window.set_message(SharedString::from("✅ Password deleted successfully!"));
                                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            }
                            Err(e) => {
                                window.set_message(SharedString::from(format!("❌ Error deleting password: {}", e)));
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    // Register handler
    let ui_handle = ui.as_weak();
    let conn_clone = Arc::clone(&conn);
    ui.on_register_clicked({
        move || {
            let ui = ui_handle.upgrade().unwrap();
            let username = ui.get_username().to_string();
            let password = ui.get_password().to_string();

            if username.is_empty() || password.is_empty() {
                ui.set_message(SharedString::from("Please enter both username and password."));
                return;
            }

            let conn_clone = Arc::clone(&conn_clone);
            let ui_handle = ui.as_weak();
            let db_paths = db_paths_for_closure.clone(); // Clone for this closure

            slint::spawn_local(async move {
                let result = register_user(conn_clone, username, password).await;

                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        match result {
                            Ok(_) => {
                                ui.set_message(SharedString::from("Registration successful!"));
                                ui.set_username(SharedString::from(""));
                                ui.set_password(SharedString::from(""));
                                slint::spawn_local(async move {
                                    if hash_all_databases(&db_paths).await.is_err() {
                                        eprintln!("Failed to hash databases after registration.");
                                    }
                                }).unwrap();
                            }
                            Err(e) => {
                                if e.to_string().contains("UNIQUE constraint failed") {
                                    ui.set_message(SharedString::from(
                                        "Username already exists. Please choose another.",
                                    ));
                                } else if e.to_string().contains("User cancelled file save") {
                                    ui.set_message(SharedString::from(
                                        "Registration failed: You must save the master key file.",
                                    ));
                                } else {
                                    ui.set_message(SharedString::from(format!("Registration failed: {}", e)));
                                }
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    let conn1_clone = Arc::clone(&conn1);
    tokio::spawn(start_websocket_server(conn1_clone));

    let ui = Arc::new(LoginWindow::new()?);
    let black_square_window = Arc::new(BlackSquareWindow::new()?);
    let db_paths_for_closure = db_paths.clone(); // Clone for the second UI setup

    // Login handler (duplicate)
    let ui_handle = ui.as_weak();
    let conn_clone = Arc::clone(&conn);
    let conn1_clone = Arc::clone(&conn1);
    let black_square_window_handle = black_square_window.as_weak();
    ui.on_login_clicked({
        move || {
            let ui = ui_handle.upgrade().unwrap();
            let username = ui.get_username().to_string();
            let password = ui.get_password().to_string();

            if username.is_empty() || password.is_empty() {
                ui.set_message(SharedString::from("Please enter a username and password."));
                return;
            }

            let conn_clone = Arc::clone(&conn_clone);
            let conn1_clone = Arc::clone(&conn1_clone);
            let ui_handle = ui.as_weak();
            let black_square_window_handle = black_square_window_handle.clone();

            slint::spawn_local(async move {
                let result = check_login(
                    &conn_clone,
                    &conn1_clone,
                    &username,
                    &password,
                    ui_handle.clone(),
                    black_square_window_handle.clone(),
                )
                .await;

                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        match result {
                            Ok(true) => {
                                ui.set_message(SharedString::from("Login successful!"));
                                ui.set_username(SharedString::from(""));
                                ui.set_password(SharedString::from(""));
                                ui.hide().unwrap();
                            }
                            Ok(false) => {
                                ui.set_message(SharedString::from("Invalid username or password."));
                            }
                            Err(e) => {
                                ui.set_message(SharedString::from(format!("Login error: {}", e)));
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    // Forgot password handler (duplicate)
    let ui_handle = ui.as_weak();
    let conn_clone = Arc::clone(&conn);
    let black_square_window_handle = black_square_window.as_weak();
    ui.on_forgot_password({
        move || {
            let ui = ui_handle.upgrade().unwrap();
            let username = ui.get_username().to_string();

            if username.is_empty() {
                ui.set_message(SharedString::from(
                    "Please enter your username before recovering your password.",
                ));
                return;
            }

            let conn_clone = Arc::clone(&conn_clone);
            let ui_handle = ui.as_weak();
            let black_square_window_handle = black_square_window_handle.clone();

            slint::spawn_local(async move {
                let username_clone = username.clone();
                let result = forgot_password(&conn_clone, &username_clone, black_square_window_handle.clone()).await;

                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        match result {
                            Ok(_) => {
                                ui.set_message(SharedString::from("Password recovery process started."));
                                ui.hide().unwrap();
                            }
                            Err(e) => {
                                ui.set_message(SharedString::from(format!("Password recovery error: {}", e)));
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    // Save password handler (duplicate)
    let conn1_clone = Arc::clone(&conn1);
    let black_square_window_handle = black_square_window.as_weak();
    black_square_window.on_savePassword({
        move || {
            let window = black_square_window_handle.upgrade().unwrap();
            let website = window.get_selected_website().to_string();
            let username_email = window.get_selected_username_email().to_string();
            let password = window.get_selected_password().to_string();


            if website.is_empty() || username_email.is_empty() || password.is_empty() {
                window.set_message(SharedString::from("All fields are required."));
                return;
            }

            let conn1_clone = Arc::clone(&conn1_clone);
            let window_handle = window.as_weak();

            slint::spawn_local(async move {
                let result = if window.get_isAddMode() {
                    add_password(&conn1_clone, &website, &username_email, &password)
                } else {
                    let id = window.get_id();
                    update_password(&conn1_clone, id, &website, &username_email, &password).await
                };
                let passwords = read_stored_passwords(&conn1_clone).await.unwrap_or_default();

                slint::invoke_from_event_loop(move || {
                    if let Some(window) = window_handle.upgrade() {
                        match result {
                            Ok(_) => {
                                window.set_message(SharedString::from(if window.get_isAddMode() {
                                    "Password added successfully!"
                                } else {
                                    "Password updated successfully!"
                                }));
                                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            }
                            Err(e) => {
                                window.set_message(SharedString::from(format!("Error: {}", e)));
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    // Edit password handler (duplicate)
    let conn1_clone = Arc::clone(&conn1);
    let black_square_window_handle = black_square_window.as_weak();
    black_square_window.on_edit({
        move |id, website, username_email, new_password| {
            let window = black_square_window_handle.upgrade().unwrap();
            let website = website.to_string();
            let username_email = username_email.to_string();
            let new_password = new_password.to_string();

            if website.is_empty() || username_email.is_empty() || new_password.is_empty() {
                window.set_message(SharedString::from("All fields must be filled."));
                return;
            }

            let conn1_clone = Arc::clone(&conn1_clone);
            let window_handle = window.as_weak();

            slint::spawn_local(async move {
                let result = update_password(&conn1_clone, id, &website, &username_email, &new_password).await;
                let passwords = read_stored_passwords(&conn1_clone).await.unwrap_or_default();

                slint::invoke_from_event_loop(move || {
                    if let Some(window) = window_handle.upgrade() {
                        match result {
                            Ok(_) => {
                                window.set_message(SharedString::from("✅ Password updated successfully!"));
                                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            }
                            Err(e) => {
                                window.set_message(SharedString::from(format!("❌ Error updating password: {}", e)));
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    // Delete password handler (duplicate)
    let conn1_clone = Arc::clone(&conn1);
    let black_square_window_handle = black_square_window.as_weak();
    black_square_window.on_deletePassword({
        move |id| {
            let window = black_square_window_handle.upgrade().unwrap();
            let conn1_clone = Arc::clone(&conn1_clone);
            let window_handle = window.as_weak();

            slint::spawn_local(async move {
                let result = delete_password(&conn1_clone, id).await;
                let passwords = read_stored_passwords(&conn1_clone).await.unwrap_or_default();

                slint::invoke_from_event_loop(move || {
                    if let Some(window) = window_handle.upgrade() {
                        match result {
                            Ok(_) => {
                                window.set_message(SharedString::from("✅ Password deleted successfully!"));
                                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            }
                            Err(e) => {
                                window.set_message(SharedString::from(format!("❌ Error deleting password: {}", e)));
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    // Register handler (duplicate)
    let ui_handle = ui.as_weak();
    let conn_clone = Arc::clone(&conn);
    ui.on_register_clicked({
        move || {
            let ui = ui_handle.upgrade().unwrap();
            let username = ui.get_username().to_string();
            let password = ui.get_password().to_string();

            if username.is_empty() || password.is_empty() {
                ui.set_message(SharedString::from("Please enter both username and password."));
                return;
            }

            let conn_clone = Arc::clone(&conn_clone);
            let ui_handle = ui.as_weak();
            let db_paths = db_paths_for_closure.clone(); // Clone for this closure

            slint::spawn_local(async move {
                let result = register_user(conn_clone, username, password).await;

                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        match result {
                            Ok(_) => {
                                ui.set_message(SharedString::from("Registration successful!"));
                                ui.set_username(SharedString::from(""));
                                ui.set_password(SharedString::from(""));
                                slint::spawn_local(async move {
                                    if hash_all_databases(&db_paths).await.is_err() {
                                        eprintln!("Failed to hash databases after registration.");
                                    }
                                }).unwrap();
                            }
                            Err(e) => {
                                if e.to_string().contains("UNIQUE constraint failed") {
                                    ui.set_message(SharedString::from(
                                        "Username already exists. Please choose another.",
                                    ));
                                } else if e.to_string().contains("User cancelled file save") {
                                    ui.set_message(SharedString::from(
                                        "Registration failed: You must save the master key file.",
                                    ));
                                } else {
                                    ui.set_message(SharedString::from(format!("Registration failed: {}", e)));
                                }
                            }
                        }
                    }
                })
                .unwrap();
            })
            .unwrap();
        }
    });

    ui.show()?;
    slint::run_event_loop()?;
    Ok(())
}

async fn check_login(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    conn1: &Arc<Pool<SqliteConnectionManager>>,
    username: &str,
    password: &str,
    _ui_handle: Weak<LoginWindow>,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<bool> {
    let conn = conn.get()?;
    let mut stmt = conn.prepare("SELECT password FROM users WHERE username = ?")?;
    let mut rows = stmt.query(params![username])?;

    if let Some(row) = rows.next()? {
        let stored_password: String = row.get(0)?;
        let parsed_hash = PasswordHash::new(&stored_password)
            .map_err(|e| anyhow!("Failed to parse password hash: {}", e))?;
        let argon2 = Argon2::default();

        if argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok() {
            let passwords = read_stored_passwords(conn1).await?;
            slint::invoke_from_event_loop(move || {
                if let Some(window) = black_square_window_handle.upgrade() {
                    window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                    window.show().unwrap();
                }
            })?;
            return Ok(true);
        }
    }
    Ok(false)
}

async fn read_stored_passwords(conn1: &Arc<Pool<SqliteConnectionManager>>) -> Result<Vec<PasswordEntry>> {
    let conn1 = conn1.get()?;
    let mut stmt = conn1.prepare("SELECT id, website, username_email, password FROM Passwords")?;
    let password_iter = stmt.query_map([], |row| {
        Ok(PasswordEntry {
            id: row.get(0)?,
            website: SharedString::from(row.get::<_, String>(1)?),
            username_email: SharedString::from(row.get::<_, String>(2)?),
            password: SharedString::from(row.get::<_, String>(3)?),
        })
    })?;
    let passwords: Vec<_> = password_iter.collect::<Result<_, _>>()?;
    Ok(passwords)
}

async fn forgot_password(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    username: &str,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<()> {
    let mut dialog = FileDialog::new();
    dialog = dialog.set_title("Select your masterkey file");

    if let Some(desktop_dir) = dirs::desktop_dir() {
        dialog = dialog.set_directory(&desktop_dir);
    }

    match dialog.pick_file() {
        Some(file_path) => {
            let file_hash = fs::read_to_string(&file_path)?;
            let conn = conn.get()?;
            let db_hash: String = conn.query_row(
                "SELECT hash FROM users WHERE username = ?1",
                params![username],
                |row| row.get(0),
            )?;

            if file_hash == db_hash {
                slint::invoke_from_event_loop(move || {
                    if let Some(window) = black_square_window_handle.upgrade() {
                        window.show().unwrap();
                    }
                })?;
            } else {
                return Err(anyhow!("Hash mismatch: Unable to recover password."));
            }
            Ok(())
        }
        None => Err(anyhow!("User cancelled file selection.")),
    }
}

async fn register_user(conn: Arc<Pool<SqliteConnectionManager>>, username: String, password: String) -> Result<()> {
    let hashed_password = hash_password(&password)?;
    let random_hash = generate_random_hash()?;

    let file_path = tokio::task::spawn_blocking(|| {
        FileDialog::new().set_file_name("masterkey.txt").save_file()
    })
    .await?.ok_or_else(|| anyhow!("User cancelled file save"))?;

    export_hash_to_file(&random_hash, &file_path).await?;

    let conn = conn.get()?;
    conn.execute(
        "INSERT INTO users (username, password, hash) VALUES (?1, ?2, ?3)",
        params![username, hashed_password, random_hash],
    )?;
    Ok(())
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash password: {:?}", e))?;
    Ok(password_hash.to_string())
}

fn generate_random_hash() -> Result<String> {
    let mut rng = OsRng;
    let random_bytes: [u8; 32] = rng.gen();
    let mut hasher = Sha256::new();
    hasher.update(&random_bytes);
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

async fn export_hash_to_file(hash: &str, file_path: &PathBuf) -> Result<()> {
    let mut file = File::create(file_path).await?;
    file.write_all(hash.as_bytes()).await?;
    Ok(())
}

async fn hash_database(file_path: &str) -> Result<String> {
    let mut file = File::open(file_path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

async fn hash_all_databases(db_paths: &[&str]) -> Result<()> {
    for db_path in db_paths {
        if Path::new(db_path).exists() {
            match hash_database(db_path).await {
                Ok(hash) => println!("{} hash: {}", db_path, hash),
                Err(e) => eprintln!("Failed to hash {}: {}", db_path, e),
            }
        } else {
            println!("{} does not exist", db_path);
        }
    }
    Ok(())
}

fn add_password(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    website: &str,
    username_email: &str,
    password: &str,
) -> Result<()> {
    let conn = conn.get()?;
    conn.execute(
        "INSERT INTO Passwords (website, username_email, password) VALUES (?1, ?2, ?3)",
        params![website, username_email, password],
    )?;
    Ok(())
}

async fn update_password(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    id: i32,
    selected_website: &str,
    selected_username_email: &str,
    selected_password: &str,
) -> Result<()> {
    let conn = conn.get()?;
    if selected_password.len() > 30 {
        return Err(anyhow!("Password exceeds 30 characters."));
    }
    let rows_affected = conn.execute(
        "UPDATE Passwords SET website = ?1, username_email = ?2, password = ?3 WHERE id = ?4",
        params![selected_website, selected_username_email, selected_password, id],
    )?;
    if rows_affected == 0 {
        return Err(anyhow!("No matching record found to update."));
    }
    Ok(())
}

async fn delete_password(conn: &Arc<Pool<SqliteConnectionManager>>, id: i32) -> Result<()> {
    let conn = conn.get()?;
    let rows_affected = conn.execute("DELETE FROM Passwords WHERE id = ?1", params![id])?;
    if rows_affected == 0 {
        return Err(anyhow!("No matching record found to delete."));
    }
    Ok(())
}