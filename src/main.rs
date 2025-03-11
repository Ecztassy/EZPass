use tokio::sync::Mutex;
use std::sync::Arc;
use rfd::FileDialog;
use rusqlite::{Connection, params};
use slint::{SharedString, ModelRc, VecModel, Weak};
use rand::{rngs::OsRng, Rng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use dirs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Added AsyncReadExt and AsyncWriteExt
use std::fs;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use futures_util::{StreamExt, SinkExt};

slint::include_modules!();

async fn start_websocket_server() {
    let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let ws_stream = accept_async(stream).await.unwrap();
            let (mut write, mut read) = ws_stream.split();

            while let Some(Ok(msg)) = read.next().await {
                println!("Received: {}", msg);
                write.send(msg).await.unwrap();
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let db_paths = vec!["login.db", "pass.db"];
    hash_all_databases(&db_paths).await?; // Fixed: Added .await

    let dblogin_path = "login.db";
    let dbpass_path = "pass.db";
    tokio::spawn(start_websocket_server());

    let conn = Arc::new(Mutex::new(
        Connection::open(dblogin_path).map_err(|e| anyhow!("Failed to open login database: {}", e))?,
    ));
    let conn1 = Arc::new(Mutex::new(
        Connection::open(dbpass_path).map_err(|e| anyhow!("Failed to open pass database: {}", e))?,
    ));

    // Initialize databases
    {
        let conn_lock = conn.lock().await;
        conn_lock.execute(
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
        let conn1_lock = conn1.lock().await;
        conn1_lock.execute(
            "CREATE TABLE IF NOT EXISTS Passwords (
                id INTEGER PRIMARY KEY,
                website TEXT NOT NULL,
                username_email TEXT NOT NULL,
                password TEXT NOT NULL CHECK(length(password) <= 3128),
                hash TEXT NOT NULL
            )",
            [],
        )?;
    }

    hash_all_databases(&db_paths).await?; // Fixed: Added .await

    let ui = Arc::new(LoginWindow::new()?);
    let black_square_window = Arc::new(BlackSquareWindow::new()?);

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
            let hash = hash_password(&password).unwrap_or_else(|e| {
                eprintln!("Failed to hash password: {}", e);
                String::new()
            });

            if website.is_empty() || username_email.is_empty() || password.is_empty() {
                window.set_message(SharedString::from("All fields are required."));
                return;
            }

            let conn1_clone = Arc::clone(&conn1_clone);
            let window_handle = window.as_weak();

            slint::spawn_local(async move {
                let result = if window.get_isAddMode() {
                    add_password(&conn1_clone, &website, &username_email, &password, &hash).await
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
            let db_paths = db_paths.clone();

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
                                    if hash_all_databases(&db_paths).await.is_err() { // Fixed: Added .await
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
    conn: &Arc<Mutex<Connection>>,
    conn1: &Arc<Mutex<Connection>>,
    username: &str,
    password: &str,
    _ui_handle: Weak<LoginWindow>,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<bool> {
    let conn_lock = conn.lock().await;
    let mut stmt = conn_lock.prepare("SELECT password FROM users WHERE username = ?")?;
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

async fn read_stored_passwords(conn1: &Arc<Mutex<Connection>>) -> Result<Vec<PasswordEntry>> {
    let conn1_lock = conn1.lock().await;
    let mut stmt = conn1_lock.prepare("SELECT id, website, username_email, password FROM Passwords")?;
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
    conn: &Arc<Mutex<Connection>>,
    username: &str,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<()> {
    let mut dialog = FileDialog::new();
    dialog = dialog.set_title("Select your masterkey file");

    if let Some(desktop_dir) = dirs::desktop_dir() { // Changed from download_dir
        dialog = dialog.set_directory(&desktop_dir);
    }

    match dialog.pick_file() {
        Some(file_path) => {
            let file_hash = fs::read_to_string(&file_path)?;
            let conn_lock = conn.lock().await;
            let db_hash: String = conn_lock.query_row(
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

async fn register_user(conn: Arc<Mutex<Connection>>, username: String, password: String) -> Result<()> {
    let hashed_password = hash_password(&password)?;
    let random_hash = generate_random_hash()?;

    // Run file dialog in a blocking thread
    let file_path = tokio::task::spawn_blocking(|| {
        FileDialog::new().set_file_name("masterkey.txt").save_file()
    })
    .await?.ok_or_else(|| anyhow!("User cancelled file save"))?;

    // Export hash to file
    export_hash_to_file(&random_hash, &file_path).await?;

    // Clone username to move it safely
    let username_clone = username.clone();

    // Lock the database connection inside a blocking task
    let conn_clone = conn.clone();
    tokio::task::spawn_blocking(move || {
        let conn_lock = tokio::task::block_in_place(|| conn_clone.blocking_lock()); // Blocking lock to avoid deadlock
        conn_lock.execute(
            "INSERT INTO users (username, password, hash) VALUES (?1, ?2, ?3)",
            params![username_clone, hashed_password, random_hash],
        )
    })
    .await??;

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
    file.write_all(hash.as_bytes()).await?; // Using AsyncWriteExt
    Ok(())
}

async fn hash_database(file_path: &str) -> Result<String> {
    let mut file = File::open(file_path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];

    loop {
        let bytes_read = file.read(&mut buffer).await?; // Fixed: Added AsyncReadExt and .await
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

async fn add_password(
    conn: &Arc<Mutex<Connection>>,
    website: &str,
    username_email: &str,
    password: &str,
    hash: &str,
) -> Result<()> {
    let conn_lock = conn.lock().await;
    conn_lock.execute(
        "INSERT INTO Passwords (website, username_email, password, hash) VALUES (?1, ?2, ?3, ?4)",
        params![website, username_email, password, hash],
    )?;
    Ok(())
}

async fn update_password(
    conn: &Arc<Mutex<Connection>>,
    id: i32,
    selected_website: &str,
    selected_username_email: &str,
    selected_password: &str,
) -> Result<()> {
    let conn_lock = conn.lock().await;
    if selected_password.len() > 30 {
        return Err(anyhow!("Password exceeds 30 characters."));
    }
    let rows_affected = conn_lock.execute(
        "UPDATE Passwords SET website = ?1, username_email = ?2, password = ?3 WHERE id = ?4",
        params![selected_website, selected_username_email, selected_password, id],
    )?;
    if rows_affected == 0 {
        return Err(anyhow!("No matching record found to update."));
    }
    Ok(())
}

async fn delete_password(conn: &Arc<Mutex<Connection>>, id: i32) -> Result<()> {
    let conn_lock = conn.lock().await;
    let rows_affected = conn_lock.execute("DELETE FROM Passwords WHERE id = ?1", params![id])?;
    if rows_affected == 0 {
        return Err(anyhow!("No matching record found to delete."));
    }
    Ok(())
}