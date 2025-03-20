// src/backend.rs

use std::sync::Arc;
use std::path::{Path, PathBuf};
use anyhow::{Result, anyhow};
use r2d2_sqlite::SqliteConnectionManager;
use r2d2::Pool;
use rusqlite::params;
use rand::{rngs::OsRng, Rng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use sha2::{Sha256, Digest};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures_util::{StreamExt, SinkExt};
use serde::{Serialize, Deserialize};
use serde_json;
use rfd::FileDialog;
use dirs;
use std::fs;
use slint::{SharedString, Weak, ModelRc, VecModel};

pub type SqlitePool = Arc<Pool<SqliteConnectionManager>>;

slint::include_modules!();

#[derive(Serialize, Deserialize)]
pub struct WebSocketResponse {
    pub password: Option<String>,
    pub username_email: Option<String>,
    pub preferences: Vec<FieldPreference>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct FieldPreference {
    pub selector: String,
    pub role: String,
}

pub fn initialize_databases(login_pool: &SqlitePool, pass_pool: &SqlitePool) -> Result<()> {
    let conn = login_pool.get()?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL CHECK(length(password) <= 128),
            hash TEXT NOT NULL
        )",
        [],
    )?;

    let conn1 = pass_pool.get()?;
    conn1.execute(
        "CREATE TABLE IF NOT EXISTS Passwords (
            id INTEGER PRIMARY KEY,
            website TEXT NOT NULL,
            username_email TEXT NOT NULL,
            password TEXT NOT NULL CHECK(length(password) <= 3128),
            hash TEXT NOT NULL
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
    Ok(())
}

pub async fn start_websocket_server(conn: SqlitePool) {
    let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
    println!("WebSocket server running on ws://127.0.0.1:9001");

    while let Ok((stream, _)) = listener.accept().await {
        let conn_clone = Arc::clone(&conn);
        tokio::spawn(async move {
            if let Ok(ws_stream) = accept_async(stream).await {
                let (mut write, mut read) = ws_stream.split();
                while let Some(msg) = read.next().await {
                    match msg {
                        Ok(Message::Text(text)) => {
                            let response = process_websocket_message(&conn_clone, &text).await;
                            let json_response = serde_json::to_string(&response).unwrap_or_else(|e| {
                                format!("{{\"error\":\"Serialization error: {}\"}}", e)
                            });
                            if let Err(e) = write.send(Message::Text(json_response.into())).await {
                                eprintln!("Failed to send response: {}", e);
                                break;
                            }
                        }
                        Ok(msg) => println!("Received non-text message: {:?}", msg),
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

async fn process_websocket_message(conn: &SqlitePool, text: &str) -> WebSocketResponse {
    if text.starts_with("PREF:") {
        let parts: Vec<&str> = text[5..].split("|").collect();
        if parts.len() == 3 {
            let website = parts[0];
            let selector = parts[1];
            let role = parts[2];
            match tokio::task::block_in_place(|| {
                save_field_preference(conn, website, selector, role)
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
    } else if text.starts_with("GET_PREFS:") {
        let website = &text[10..];
        match tokio::task::block_in_place(|| get_field_preferences(conn, website)) {
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
        match tokio::task::block_in_place(|| retrieve_password(conn, website)) {
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
    } else if text.starts_with("ADD_PASSWORD:") {
        let parts: Vec<&str> = text[12..].split("|").collect();
        if parts.len() == 3 {
            let website = parts[0];
            let username_email = parts[1];
            let password = parts[2];
            match add_password(conn, website, username_email, password).await {
                Ok(()) => WebSocketResponse {
                    password: Some(password.to_string()),
                    username_email: Some(username_email.to_string()),
                    preferences: Vec::new(),
                    error: None,
                },
                Err(e) => WebSocketResponse {
                    password: None,
                    username_email: None,
                    preferences: Vec::new(),
                    error: Some(format!("Failed to add password: {}", e)),
                },
            }
        } else {
            WebSocketResponse {
                password: None,
                username_email: None,
                preferences: Vec::new(),
                error: Some("Invalid ADD_PASSWORD format".to_string()),
            }
        }
    } else {
        match tokio::task::block_in_place(|| retrieve_password_and_prefs(conn, text)) {
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
    }
}

pub fn retrieve_password_and_prefs(conn: &SqlitePool, website: &str) -> Result<(Option<String>, Option<String>, Vec<FieldPreference>)> {
    let conn = conn.get()?;
    let mut stmt = conn.prepare("SELECT password, username_email FROM Passwords WHERE website = ?1")?;
    let mut rows = stmt.query(params![website])?;
    let (password, username_email) = if let Some(row) = rows.next()? {
        (Some(row.get(0)?), Some(row.get(1)?))
    } else {
        (None, None)
    };
    let prefs = get_field_preferences(conn, website)?;
    Ok((password, username_email, prefs))
}

pub fn save_field_preference(conn: &SqlitePool, website: &str, selector: &str, role: &str) -> Result<()> {
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

pub fn get_field_preferences(conn: &SqlitePool, website: &str) -> Result<Vec<FieldPreference>> {
    let conn = conn.get()?;
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

pub fn retrieve_password(conn: &SqlitePool, website: &str) -> Result<Option<String>> {
    let conn = conn.get()?;
    let mut stmt = conn.prepare("SELECT password FROM Passwords WHERE website = ?1")?;
    let mut rows = stmt.query(params![website])?;
    if let Some(row) = rows.next()? {
        let password: String = row.get(0)?;
        Ok(Some(password))
    } else {
        Ok(None)
    }
}

pub async fn check_login(
    login_pool: &SqlitePool,
    pass_pool: &SqlitePool,
    username: &str,
    password: &str,
    _ui_handle: Weak<LoginWindow>,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<bool> {
    let conn = login_pool.get()?;
    let mut stmt = conn.prepare("SELECT password FROM users WHERE username = ?")?;
    let mut rows = stmt.query(params![username])?;

    if let Some(row) = rows.next()? {
        let stored_password: String = row.get(0)?;
        let parsed_hash = PasswordHash::new(&stored_password)
            .map_err(|e| anyhow!("Failed to parse password hash: {}", e))?;
        let argon2 = Argon2::default();

        if argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok() {
            let passwords = read_stored_passwords(pass_pool).await?;
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

pub async fn read_stored_passwords(conn: &SqlitePool) -> Result<Vec<PasswordEntry>> {
    let conn = conn.get()?;
    let mut stmt = conn.prepare("SELECT id, website, username_email, password FROM Passwords")?;
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

pub async fn forgot_password(
    conn: &SqlitePool,
    username: &str,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<()> {
    let mut dialog = FileDialog::new().set_title("Select your masterkey file");
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

pub async fn register_user(conn: SqlitePool, username: String, password: String) -> Result<()> {
    let hashed_password = hash_password(&password)?;
    let random_hash = generate_random_hash()?;

    let file_path = tokio::task::spawn_blocking(|| {
        FileDialog::new().set_file_name("masterkey.txt").save_file()
    }).await?.ok_or_else(|| anyhow!("User cancelled file save"))?;

    export_hash_to_file(&random_hash, &file_path).await?;

    let conn = conn.get()?;
    conn.execute(
        "INSERT INTO users (username, password, hash) VALUES (?1, ?2, ?3)",
        params![username, hashed_password, random_hash],
    )?;
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash password: {:?}", e))?;
    Ok(password_hash.to_string())
}

pub fn generate_random_hash() -> Result<String> {
    let mut rng = OsRng;
    let random_bytes: [u8; 32] = rng.gen();
    let mut hasher = Sha256::new();
    hasher.update(&random_bytes);
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

pub async fn export_hash_to_file(hash: &str, file_path: &PathBuf) -> Result<()> {
    let mut file = File::create(file_path).await?;
    file.write_all(hash.as_bytes()).await?;
    Ok(())
}

pub async fn hash_database(file_path: &str) -> Result<String> {
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

pub async fn hash_all_databases(db_paths: &[&str]) -> Result<()> {
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

pub async fn add_password(
    conn: &SqlitePool,
    website: &str,
    username_email: &str,
    password: &str,
) -> Result<()> {
    let conn = conn.get()?;
    conn.execute(
        "INSERT INTO Passwords (website, username_email, password, hash) VALUES (?1, ?2, ?3, '')",
        params![website, username_email, password],
    )?;
    Ok(())
}

pub async fn update_password(
    conn: &SqlitePool,
    id: i32,
    website: &str,
    username_email: &str,
    password: &str,
) -> Result<()> {
    let conn = conn.get()?;
    if password.len() > 30 {
        return Err(anyhow!("Password exceeds 30 characters."));
    }
    let rows_affected = conn.execute(
        "UPDATE Passwords SET website = ?1, username_email = ?2, password = ?3 WHERE id = ?4",
        params![website, username_email, password, id],
    )?;
    if rows_affected == 0 {
        return Err(anyhow!("No matching record found to update."));
    }
    Ok(())
}

pub async fn delete_password(conn: &SqlitePool, id: i32) -> Result<()> {
    let conn = conn.get()?;
    let rows_affected = conn.execute("DELETE FROM Passwords WHERE id = ?1", params![id])?;
    if rows_affected == 0 {
        return Err(anyhow!("No matching record found to delete."));
    }
    Ok(())
}