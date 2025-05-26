#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use std::sync::Arc;
use rand::RngCore;
use rfd::AsyncFileDialog;
use slint::{ ModelRc, VecModel, Weak };
use rand::rngs::OsRng;
use argon2::{ Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString };
use anyhow::{ Result, anyhow };
use sha2::{ Sha256, Digest };
use std::path::{ Path, PathBuf };
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::{ accept_async, tungstenite::Message };
use futures_util::{ StreamExt, SinkExt };
use sqlx::{ Pool, SqlitePool, Sqlite, sqlite::SqlitePoolOptions };
use serde::{ Serialize, Deserialize };
use serde_json;
use tokio::sync::mpsc::{ channel, Sender, Receiver };
use once_cell::sync::Lazy;
use std::sync::Mutex;
use simple_crypt::{ encrypt, decrypt };
use hex;
use dirs;
use tokio::fs;

slint::include_modules!();

static WEBSOCKET_TASK: Lazy<Mutex<Option<tokio::task::JoinHandle<()>>>> = Lazy::new(||
    Mutex::new(None)
);
static WEBSOCKET_SHUTDOWN: Lazy<Mutex<Option<watch::Sender<bool>>>> = Lazy::new(||
    Mutex::new(None)
);
static ENCRYPTION_KEY: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

const DATABASE_DIR: &str = "databases";

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: std::alloc::System = std::alloc::System;

#[derive(Serialize, Deserialize, Clone)]
struct DatabaseConfig {
    name: String,
    db_path: PathBuf,
    masterkey_path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Config {
    databases: Vec<DatabaseConfig>,
}

#[derive(Serialize, Deserialize, Debug)]
struct WebSocketResponse {
    password: Option<String>,
    username_email: Option<String>,
    preferences: Vec<FieldPreference>,
    save_allowed: Option<bool>,
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    multiple_accounts: Option<Vec<(String, String)>>, // (password, username_email) pairs
}

#[derive(Debug)]
enum UiUpdate {
    AddPasswordSuccess(Vec<PasswordEntry>),
    Error(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, sqlx::FromRow)]
struct FieldPreference {
    selector: String,
    role: String,
}

fn get_database_path(name: &str) -> PathBuf {
    let dir = dirs
        ::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("EZPass")
        .join(DATABASE_DIR);
    dir.join(format!("{}.db", name))
}

async fn load_config() -> Result<Config> {
    let config_dir = dirs
        ::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("EZPass");
    tokio::fs::create_dir_all(&config_dir).await?;
    let config_path = config_dir.join("config.json");
    if config_path.exists() {
        let config_str = tokio::fs::read_to_string(&config_path).await?;
        Ok(serde_json::from_str(&config_str)?)
    } else {
        Ok(Config { databases: Vec::with_capacity(4) })
    }
}

async fn save_config(config: &Config) -> Result<()> {
    let config_dir = dirs
        ::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("EZPass");
    tokio::fs::create_dir_all(&config_dir).await?;
    let config_path = config_dir.join("config.json");
    let config_str = serde_json::to_string_pretty(config)?;
    tokio::fs::write(&config_path, config_str.as_bytes()).await?;
    Ok(())
}

async fn setup_database(db_path: &Path) -> Result<SqlitePool, anyhow::Error> {
    let db_url = format!("sqlite:{}", db_path.display());
    println!("Connecting to database at: {}", db_url);

    // Ensure the file exists (SQLite won't create it automatically if the directory is writable)
    if !db_path.exists() {
        println!("Database file does not exist, creating: {:?}", db_path);
        if let Err(e) = fs::File::create(db_path).await {
            return Err(anyhow!("Failed to create database file: {}", e));
        }
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect(&db_url).await
        .map_err(|e| anyhow!("Failed to connect to database: {}", e))?;

    println!("Database connected, creating tables...");
    sqlx
        ::query(
            "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL CHECK(length(password) <= 128),
            salt TEXT NOT NULL,
            enc_key_encrypted_with_pwd BLOB NOT NULL,
            enc_key_encrypted_with_masterkey BLOB NOT NULL,
            enc_key_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS Passwords (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            username_email TEXT NOT NULL,
            password BLOB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS FieldPreferences (
            id INTEGER PRIMARY KEY,
            website TEXT NOT NULL,
            selector TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('Username', 'Password')),
            UNIQUE(website, selector)
        );
        CREATE TABLE IF NOT EXISTS WebsitePreferences (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            save_password INTEGER NOT NULL DEFAULT 1,
            UNIQUE(user_id, website),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );"
        )
        .execute(&pool).await
        .map_err(|e| anyhow!("Failed to create tables: {}", e))?;

    println!("Tables created successfully");
    Ok(pool)
}

async fn import_database(
    db_file: &Path,
    masterkey_file: &Path,
    username: Option<&str>
) -> Result<(i32, Pool<Sqlite>)> {
    let mut config = load_config().await?;
    let name = db_file
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("Invalid database name"))?;

    // Generate unique db_path
    let mut db_path = get_database_path(name);
    let mut masterkey_path = db_path.with_extension("masterkey");
    let mut counter = 1;
    let base_name = name.to_string();
    while config.databases.iter().any(|db| db.db_path == db_path) {
        let new_name = format!("{}_{}", base_name, counter);
        db_path = get_database_path(&new_name);
        masterkey_path = db_path.with_extension("masterkey");
        counter += 1;
    }

    // Ensure the target directory exists
    if let Some(parent) = db_path.parent() {
        println!("Creating directory: {:?}", parent);
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return Err(anyhow!("Failed to create directory {:?}: {}", parent, e));
        }
    }

    // Copy files with error handling
    if !db_file.exists() {
        return Err(anyhow!("Source database file does not exist: {:?}", db_file));
    }
    if !masterkey_file.exists() {
        return Err(anyhow!("Source masterkey file does not exist: {:?}", masterkey_file));
    }
    tokio::fs
        ::copy(db_file, &db_path).await
        .map_err(|e|
            anyhow!("Failed to copy database file from {:?} to {:?}: {}", db_file, db_path, e)
        )?;
    tokio::fs
        ::copy(masterkey_file, &masterkey_path).await
        .map_err(|e|
            anyhow!(
                "Failed to copy masterkey file from {:?} to {:?}: {}",
                masterkey_file,
                masterkey_path,
                e
            )
        )?;

    // Set up database connection
    let pool = setup_database(&db_path).await?;

    // Read and verify masterkey
    let masterkey_hex = tokio::fs
        ::read_to_string(&masterkey_path).await
        .map_err(|e| anyhow!("Failed to read masterkey file {:?}: {}", masterkey_path, e))?;
    let masterkey = hex
        ::decode(&masterkey_hex)
        .map_err(|e| anyhow!("Invalid masterkey format in {:?}: {}", masterkey_path, e))?;

    // Verify user and encryption key
    let username_to_check = username.unwrap_or("default");
    let row = sqlx
        ::query_as::<_, (i32, Vec<u8>, String)>(
            "SELECT id, enc_key_encrypted_with_masterkey, enc_key_hash FROM users WHERE username = ?"
        )
        .bind(username_to_check)
        .fetch_optional(&pool).await
        .map_err(|e| anyhow!("Database query failed: {}", e))?;

    let (user_id, enc_key_encrypted, enc_key_hash) = row.ok_or_else(||
        anyhow!("User '{}' not found in imported database", username_to_check)
    )?;

    let decrypted_key = decrypt(&enc_key_encrypted, &masterkey).map_err(|e|
        anyhow!("Failed to decrypt encryption key: {}", e)
    )?;
    let mut hasher = Sha256::default();
    hasher.update(&decrypted_key);
    if hex::encode(hasher.finalize()) != enc_key_hash {
        // Cleanup on failure
        if let Err(e) = tokio::fs::remove_file(&db_path).await {
            println!("Failed to clean up db_path {:?}: {}", db_path, e);
        }
        if let Err(e) = tokio::fs::remove_file(&masterkey_path).await {
            println!("Failed to clean up masterkey_path {:?}: {}", masterkey_path, e);
        }
        return Err(anyhow!("Masterkey does not match the database"));
    }

    // Update config
    config.databases.push(DatabaseConfig {
        name: db_path.file_stem().unwrap().to_str().unwrap().to_string(),
        db_path: db_path.clone(),
        masterkey_path: masterkey_path.clone(),
    });
    save_config(&config).await.map_err(|e| anyhow!("Failed to save config: {}", e))?;

    *ENCRYPTION_KEY.lock().unwrap() = Some(decrypted_key);
    println!("Database imported successfully: {:?}", db_path);
    Ok((user_id, pool))
}

async fn register_user(
    db_path: &Path,
    username: String,
    password: String
) -> Result<SqlitePool, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = hash_password(&password, &salt)?;

    let mut enc_key = vec![0u8; 32];
    OsRng.fill_bytes(&mut enc_key);

    let pwd_key = derive_key(&password, &salt.to_string())?;
    let enc_key_encrypted_with_pwd = encrypt(&enc_key, &pwd_key)?;

    let mut masterkey = vec![0u8; 32];
    OsRng.fill_bytes(&mut masterkey);
    let enc_key_encrypted_with_masterkey = encrypt(&enc_key, &masterkey)?;

    let mut hasher = Sha256::default();
    hasher.update(&enc_key);
    let enc_key_hash = hex::encode(hasher.finalize());

    let masterkey_path = db_path.with_extension("masterkey");
    fs::write(&masterkey_path, hex::encode(&masterkey)).await?;

    let pool = setup_database(db_path).await?;
    sqlx
        ::query(
            "INSERT INTO users (username, password, salt, enc_key_encrypted_with_pwd, enc_key_encrypted_with_masterkey, enc_key_hash) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&username)
        .bind(&hashed_password)
        .bind(salt.as_str())
        .bind(&enc_key_encrypted_with_pwd)
        .bind(&enc_key_encrypted_with_masterkey)
        .bind(&enc_key_hash)
        .execute(&pool).await?;

    *ENCRYPTION_KEY.lock().unwrap() = Some(enc_key);
    Ok(pool)
}

async fn check_login(
    db_path: &Path,
    username: &str,
    password: &str,
    black_square_window_handle: Weak<BlackSquareWindow>
) -> Result<(bool, i32, Pool<Sqlite>)> {
    let pool = setup_database(db_path).await?;
    let row = sqlx
        ::query_as::<_, (i32, String, String, Vec<u8>, String)>(
            "SELECT id, password, salt, enc_key_encrypted_with_pwd, enc_key_hash FROM users WHERE username = ?"
        )
        .bind(username)
        .fetch_optional(&pool).await?;

    if let Some((user_id, stored_password, salt, enc_key_encrypted_with_pwd, enc_key_hash)) = row {
        let parsed_hash = PasswordHash::new(&stored_password).map_err(|e| anyhow!(e))?;
        if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok() {
            let pwd_key = derive_key(password, &salt)?;
            let enc_key_candidate = decrypt(&enc_key_encrypted_with_pwd, &pwd_key)?;
            let mut hasher = Sha256::default();
            hasher.update(&enc_key_candidate);
            if hex::encode(hasher.finalize()) == enc_key_hash {
                *ENCRYPTION_KEY.lock().unwrap() = Some(enc_key_candidate.clone());
                let passwords = read_stored_passwords(&pool, user_id, enc_key_candidate).await?;
                let is_passwords_empty = passwords.is_empty();
                slint::invoke_from_event_loop({
                    let black_square_window_handle = black_square_window_handle.clone();
                    move || {
                        if let Some(window) = black_square_window_handle.upgrade() {
                            window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            window.show().unwrap();
                            if is_passwords_empty {
                                window.set_message("Nenhuma Password encontrada.".into());
                            }
                        }
                    }
                })?;
                return Ok((true, user_id, pool));
            }
        }
    }
    Ok((false, 0, pool))
}

async fn check_masterkey_login(
    db_path: &Path,
    masterkey_path: &Path,
    username: &str,
    black_square_window_handle: Weak<BlackSquareWindow>
) -> Result<(bool, i32, Pool<Sqlite>)> {
    let masterkey_hex = tokio::fs::read_to_string(masterkey_path).await?;
    let masterkey = hex
        ::decode(&masterkey_hex)
        .map_err(|e| anyhow!("Arquivo masterkey inválido: {}", e))?;
    let pool = setup_database(db_path).await?;
    let row = sqlx
        ::query_as::<_, (i32, Vec<u8>, String)>(
            "SELECT id, enc_key_encrypted_with_masterkey, enc_key_hash FROM users WHERE username = ?"
        )
        .bind(username)
        .fetch_optional(&pool).await?;

    if let Some((user_id, enc_key_encrypted_with_masterkey, enc_key_hash)) = row {
        let enc_key_candidate = decrypt(&enc_key_encrypted_with_masterkey, &masterkey)?;
        let mut hasher = Sha256::default();
        hasher.update(&enc_key_candidate);
        if hex::encode(hasher.finalize()) == enc_key_hash {
            *ENCRYPTION_KEY.lock().unwrap() = Some(enc_key_candidate.clone());
            let passwords = read_stored_passwords(&pool, user_id, enc_key_candidate).await?;
            let is_passwords_empty = passwords.is_empty();
            slint::invoke_from_event_loop({
                let black_square_window_handle = black_square_window_handle.clone();
                move || {
                    if let Some(window) = black_square_window_handle.upgrade() {
                        window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                        window.show().unwrap();
                        if is_passwords_empty {
                            window.set_message("Sem passwords adicionadas.".into());
                        }
                    }
                }
            })?;
            return Ok((true, user_id, pool));
        }
    }
    Ok((false, 0, pool))
}

async fn read_stored_passwords(
    pool: &Pool<Sqlite>,
    user_id: i32,
    key: Vec<u8>
) -> Result<Vec<PasswordEntry>> {
    let rows = sqlx
        ::query_as::<_, (i32, String, String, Vec<u8>)>(
            "SELECT id, website, username_email, password FROM Passwords WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_all(pool).await?;

    let passwords = rows
        .into_iter()
        .map(|(id, website, username_email, encrypted_password)| {
            let password = decrypt_password(&encrypted_password, &key).unwrap_or_else(|e|
                format!("Formatação falhou {}", e)
            );
            PasswordEntry {
                id,
                website: website.into(),
                username_email: username_email.into(),
                password: password.into(),
            }
        })
        .collect();

    Ok(passwords)
}

fn setup_login_handler(ui: &Arc<LoginWindow>, black_square_window: &Arc<BlackSquareWindow>) {
    let ui_weak = ui.as_weak();
    let black_weak = black_square_window.as_weak();

    ui.on_login_clicked({
        let ui_weak = ui_weak.clone();
        let black_weak = black_weak.clone();
        move || {
            let ui = ui_weak.upgrade().unwrap();
            let (username, password) = (
                ui.get_username().to_string(),
                ui.get_password().to_string(),
            );
            if username.is_empty() || password.is_empty() {
                ui.set_message("Por favor ensira o nome de utilizador e password.".into());
                return;
            }

            slint
                ::spawn_local({
                    let ui_weak = ui_weak.clone();
                    let black_weak = black_weak.clone();
                    async move {
                        let db_path = match
                            AsyncFileDialog::new()
                                .set_title("Selecionar arquivo de DB.")
                                .pick_file().await
                        {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint
                                    ::invoke_from_event_loop(move || {
                                        ui_weak
                                            .upgrade()
                                            .map(|ui| ui.set_message("Seleção cancelada".into()));
                                    })
                                    .unwrap();
                                return;
                            }
                        };
                        let config = load_config().await.unwrap();
                        let masterkey_path = config.databases
                            .iter()
                            .find(|db| db.db_path == db_path)
                            .map(|c| c.masterkey_path.clone())
                            .unwrap_or_else(|| db_path.with_extension("masterkey"));

                        let result = check_login(
                            &db_path,
                            &username,
                            &password,
                            black_weak.clone()
                        ).await;
                        slint
                            ::invoke_from_event_loop({
                                let ui_weak = ui_weak.clone();
                                let black_weak = black_weak.clone();
                                move || {
                                    if let Some(ui) = ui_weak.upgrade() {
                                        match result {
                                            Ok((true, user_id, pool)) => {
                                                ui.set_message("Login bem-sucessido!".into());
                                                ui.set_username("".into());
                                                ui.set_password("".into());
                                                ui.hide().unwrap();
                                                if let Some(window) = black_weak.upgrade() {
                                                    setup_password_handlers(
                                                        &window,
                                                        &pool,
                                                        user_id,
                                                        db_path,
                                                        masterkey_path
                                                    );
                                                }
                                            }
                                            Ok((false, _, _)) =>
                                                ui.set_message(
                                                    "Utilizador e password inválida.".into()
                                                ),
                                            Err(e) =>
                                                ui.set_message(
                                                    format!("Erro de login: {}", e).into()
                                                ),
                                        }
                                    }
                                }
                            })
                            .unwrap();
                    }
                })
                .unwrap();
        }
    });

    ui.on_forgot_password({
        let ui_weak = ui_weak.clone();
        let black_weak = black_weak.clone();
        move || {
            let ui = ui_weak.upgrade().unwrap();
            let username = ui.get_username().to_string();
            if username.is_empty() {
                ui.set_message("Por favor insira o utilizador.".into());
                return;
            }

            slint
                ::spawn_local({
                    let ui_weak = ui_weak.clone();
                    let black_weak = black_weak.clone();
                    async move {
                        let db_path = match
                            AsyncFileDialog::new()
                                .set_title("Selecionar arquivo de DB")
                                .pick_file().await
                        {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint
                                    ::invoke_from_event_loop(move || {
                                        ui_weak
                                            .upgrade()
                                            .map(|ui| ui.set_message("Seleção cancelada".into()));
                                    })
                                    .unwrap();
                                return;
                            }
                        };
                        let masterkey_path = match
                            AsyncFileDialog::new().set_title("Selecionar chave").pick_file().await
                        {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint
                                    ::invoke_from_event_loop(move || {
                                        ui_weak
                                            .upgrade()
                                            .map(|ui| ui.set_message("Seleção cancelada".into()));
                                    })
                                    .unwrap();
                                return;
                            }
                        };

                        let result = check_masterkey_login(
                            &db_path,
                            &masterkey_path,
                            &username,
                            black_weak.clone()
                        ).await;
                        slint
                            ::invoke_from_event_loop({
                                let ui_weak = ui_weak.clone();
                                let black_weak = black_weak.clone();
                                move || {
                                    if let Some(ui) = ui_weak.upgrade() {
                                        match result {
                                            Ok((true, user_id, pool)) => {
                                                ui.set_message(
                                                    "Login com a masterkey bem sucedida!".into()
                                                );
                                                ui.hide().unwrap();
                                                if let Some(window) = black_weak.upgrade() {
                                                    setup_password_handlers(
                                                        &window,
                                                        &pool,
                                                        user_id,
                                                        db_path,
                                                        masterkey_path
                                                    );
                                                }
                                            }
                                            Ok((false, _, _)) =>
                                                ui.set_message("Masterkey inválida.".into()),
                                            Err(e) => ui.set_message(format!("Erro: {}", e).into()),
                                        }
                                    }
                                }
                            })
                            .unwrap();
                    }
                })
                .unwrap();
        }
    });
}

async fn setup_register_handler(ui: Arc<LoginWindow>) {
    let ui_weak = ui.as_weak();
    ui.on_register_clicked({
        let ui_weak = ui_weak.clone();
        move || {
            let ui = match ui_weak.upgrade() {
                Some(ui) => ui,
                None => {
                    return;
                } // UI gone, exit silently
            };
            let (username, password) = (
                ui.get_username().to_string(),
                ui.get_password().to_string(),
            );
            if username.is_empty() || password.is_empty() {
                ui.set_message("Por favor insira utilizador e password.".into());
                return;
            }

            let ui_weak_inner = ui_weak.clone();
            match
                slint::spawn_local(async move {
                    let dialog = AsyncFileDialog::new()
                        .set_file_name("Nova_database.db")
                        .set_title("Salvar Nova Database");
                    let db_path = match dialog.save_file().await {
                        Some(handle) => {
                            let path = handle.path().to_path_buf();
                            println!("Selected db_path: {:?}", path); // Log the path
                            if let Some(parent) = path.parent() {
                                println!("Creating directory: {:?}", parent);
                                if let Err(e) = fs::create_dir_all(parent).await {
                                    println!("Failed to create directory: {}", e);
                                    slint
                                        ::invoke_from_event_loop(move || {
                                            if let Some(ui) = ui_weak_inner.upgrade() {
                                                ui.set_message(
                                                    format!("Falha ao criar diretório: {}", e).into()
                                                );
                                            }
                                        })
                                        .ok();
                                    return;
                                }
                                println!("Directory created successfully: {:?}", parent);
                            }
                            path
                        }
                        None => {
                            println!("Save file dialog canceled");
                            slint
                                ::invoke_from_event_loop(move || {
                                    if let Some(ui) = ui_weak_inner.upgrade() {
                                        ui.set_message("Registro cancelado".into());
                                    }
                                })
                                .ok();
                            return;
                        }
                    };

                    println!("Attempting to register user with db_path: {:?}", db_path);
                    let db_name = db_path.file_stem().unwrap().to_str().unwrap().to_string();
                    match register_user(&db_path, username, password).await {
                        Ok(_pool) => {
                            match load_config().await {
                                Ok(mut config) => {
                                    if !config.databases.iter().any(|db| db.db_path == db_path) {
                                        config.databases.push(DatabaseConfig {
                                            name: db_name,
                                            db_path: db_path.clone(),
                                            masterkey_path: db_path.with_extension("masterkey"),
                                        });
                                        if let Err(e) = save_config(&config).await {
                                            println!("Failed to save config: {}", e);
                                            slint
                                                ::invoke_from_event_loop(move || {
                                                    if let Some(ui) = ui_weak_inner.upgrade() {
                                                        ui.set_message(
                                                            format!("Falha ao salvar config: {}", e).into()
                                                        );
                                                    }
                                                })
                                                .ok();
                                            return;
                                        }
                                    }
                                    slint
                                        ::invoke_from_event_loop(move || {
                                            if let Some(ui) = ui_weak_inner.upgrade() {
                                                ui.set_message("Registro bem sucedido!".into());
                                                ui.set_username("".into());
                                                ui.set_password("".into());
                                            }
                                        })
                                        .ok();
                                }
                                Err(e) => {
                                    println!("Failed to load config: {}", e);
                                    slint
                                        ::invoke_from_event_loop(move || {
                                            if let Some(ui) = ui_weak_inner.upgrade() {
                                                ui.set_message(
                                                    format!("Falha ao carregar config: {}", e).into()
                                                );
                                            }
                                        })
                                        .ok();
                                }
                            }
                        }
                        Err(e) => {
                            println!("Registration failed: {}", e);
                            let error_message = e.to_string();
                            slint
                                ::invoke_from_event_loop(move || {
                                    if let Some(ui) = ui_weak_inner.upgrade() {
                                        ui.set_message(
                                            format!("Falha no registro: {}", error_message).into()
                                        );
                                    }
                                })
                                .ok();
                        }
                    }
                })
            {
                Ok(_) => (),
                Err(e) => {
                    println!("Failed to spawn local task: {}", e);
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_message(format!("Erro interno ao processar registro: {}", e).into());
                    }
                }
            }
        }
    });
}

async fn setup_import_handler(ui: Arc<LoginWindow>, black_square_window: Arc<BlackSquareWindow>) {
    let ui_weak = ui.as_weak();
    let black_weak = black_square_window.as_weak();

    ui.on_importeddb({
        let ui_weak = ui_weak.clone();
        let black_weak = black_weak.clone();
        move || {
            let ui_weak = ui_weak.clone();
            let black_weak = black_weak.clone();
            slint
                ::spawn_local(async move {
                    let db_file = match
                        AsyncFileDialog::new()
                            .set_title("Select database file to import:")
                            .add_filter("Database", &["db"])
                            .pick_file().await
                    {
                        Some(handle) => handle.path().to_path_buf(),
                        None => {
                            slint::invoke_from_event_loop(move || {
                                ui_weak
                                    .upgrade()
                                    .map(|ui| ui.set_message("Database selection canceled".into()));
                            })?;
                            return Ok::<(), anyhow::Error>(());
                        }
                    };
                    let masterkey_file = match
                        AsyncFileDialog::new()
                            .set_title("Select Masterkey File")
                            .add_filter("Masterkey File", &["masterkey"])
                            .pick_file().await
                    {
                        Some(handle) => handle.path().to_path_buf(),
                        None => {
                            slint::invoke_from_event_loop(move || {
                                ui_weak
                                    .upgrade()
                                    .map(|ui|
                                        ui.set_message("Masterkey selection canceled.".into())
                                    );
                            })?;
                            return Ok(());
                        }
                    };

                    match
                        import_database(
                            &db_file,
                            &masterkey_file,
                            Some(&ui_weak.upgrade().unwrap().get_username().to_string())
                        ).await
                    {
                        Ok((user_id, pool)) => {
                            let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                            let passwords = read_stored_passwords(&pool, user_id, key).await?;

                            slint::invoke_from_event_loop({
                                let ui_weak = ui_weak.clone();
                                let black_weak = black_weak.clone();
                                move || {
                                    if let Some(window) = black_weak.upgrade() {
                                        window.set_password_entries(
                                            ModelRc::new(VecModel::from(passwords))
                                        );
                                        window.show().unwrap();
                                        setup_password_handlers(
                                            &window,
                                            &pool,
                                            user_id,
                                            db_file.clone(),
                                            masterkey_file.clone()
                                        );
                                    }
                                    if let Some(ui) = ui_weak.upgrade() {
                                        ui.set_message("Database imported successfully!".into());
                                        ui.hide().unwrap();
                                    }
                                }
                            })?;
                        }
                        Err(e) =>
                            slint::invoke_from_event_loop(move || {
                                ui_weak
                                    .upgrade()
                                    .map(|ui|
                                        ui.set_message(format!("Import failed: {}", e).into())
                                    );
                            })?,
                    }
                    Ok(())
                })
                .unwrap();
        }
    });
}

fn setup_export_handler(
    black_square_window: &BlackSquareWindow,
    db_path: PathBuf,
    masterkey_path: PathBuf
) {
    let black_weak = black_square_window.as_weak();
    black_square_window.on_export({
        let db_path = db_path.clone();
        let masterkey_path = masterkey_path.clone();
        move || {
            let black_weak = black_weak.clone();
            let db_path = db_path.clone();
            let masterkey_path = masterkey_path.clone();
            slint
                ::spawn_local(async move {
                    let db_file = match
                        AsyncFileDialog::new().set_file_name("exportada.db").save_file().await
                    {
                        Some(handle) => handle.path().to_path_buf(),
                        None => {
                            slint
                                ::invoke_from_event_loop(move || {
                                    black_weak
                                        .upgrade()
                                        .map(|w|
                                            w.set_message(
                                                "Exportação da database cancelada.".into()
                                            )
                                        );
                                })
                                .unwrap();
                            return;
                        }
                    };
                    if let Err(e) = tokio::fs::copy(&db_path, &db_file).await {
                        slint
                            ::invoke_from_event_loop(move || {
                                black_weak
                                    .upgrade()
                                    .map(|w|
                                        w.set_message(
                                            format!("Exportação da database falhou. {}", e).into()
                                        )
                                    );
                            })
                            .unwrap();
                        return;
                    }
                    let masterkey_file = match
                        AsyncFileDialog::new()
                            .set_file_name("exportada.masterkey")
                            .save_file().await
                    {
                        Some(handle) => handle.path().to_path_buf(),
                        None => {
                            slint
                                ::invoke_from_event_loop(move || {
                                    black_weak
                                        .upgrade()
                                        .map(|w|
                                            w.set_message(
                                                "Exportação da masterkey cancelada".into()
                                            )
                                        );
                                })
                                .unwrap();
                            return;
                        }
                    };
                    (
                        match tokio::fs::copy(&masterkey_path, &masterkey_file).await {
                            Ok(_) =>
                                slint::invoke_from_event_loop(move || {
                                    black_weak
                                        .upgrade()
                                        .map(|w|
                                            w.set_message(
                                                "Database e masterkey exportadas com sucesso!".into()
                                            )
                                        );
                                }),
                            Err(e) =>
                                slint::invoke_from_event_loop(move || {
                                    black_weak
                                        .upgrade()
                                        .map(|w|
                                            w.set_message(
                                                format!("Exportação da masterkey falhou: {}", e).into()
                                            )
                                        );
                                }),
                        }
                    ).unwrap();
                })
                .unwrap();
        }
    });
}

async fn start_websocket_server(pool: Pool<Sqlite>, ui_sender: Sender<UiUpdate>, user_id: i32) {
    println!("Iniciando websocket no 127.0.0.1:9001...");
    let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    *WEBSOCKET_SHUTDOWN.lock().unwrap() = Some(shutdown_tx);

    'websocket_loop: while
        let Ok((stream, _)) =
            (tokio::select! {
        result = listener.accept() => result,
        _ = shutdown_rx.changed() => {
            if *shutdown_rx.borrow() {
                println!("Servidor websocket a desligar...");
                break 'websocket_loop;
            }
            println!("websocket recebeu pedido de desligar mas não terminou");
            continue 'websocket_loop;
        }
    })
    {
        let pool_clone = pool.clone();
        let ui_sender_clone = ui_sender.clone();
        tokio::spawn(async move {
            if let Ok(ws_stream) = accept_async(stream).await {
                let (mut write, mut read) = ws_stream.split();
                while let Some(msg) = read.next().await {
                    if let Ok(Message::Text(text)) = msg {
                        let response = process_websocket_message(
                            &pool_clone,
                            &text,
                            &ui_sender_clone,
                            user_id
                        ).await;
                        let json_response = serde_json
                            ::to_string(&response)
                            .unwrap_or_else(|e|
                                format!("{{\"error\":\"Erro de formatação: {}\"}}", e)
                            );
                        if write.send(Message::Text(json_response.into())).await.is_err() {
                            println!("Falha na mensagem do websocket, a terminar ligação...");
                            break;
                        }
                    }
                }
            }
        });
    }
    println!("Websocket desligou.");
}

async fn save_website_preference(
    pool: &Pool<Sqlite>,
    user_id: i32,
    website: &str,
    save_password: bool
) -> Result<()> {
    sqlx
        ::query(
            "INSERT OR REPLACE INTO WebsitePreferences (user_id, website, save_password) VALUES (?, ?, ?)"
        )
        .bind(user_id)
        .bind(website)
        .bind(save_password as i32)
        .execute(pool).await?;
    Ok(())
}

async fn get_website_preference(pool: &Pool<Sqlite>, user_id: i32, website: &str) -> Result<bool> {
    let save_password: Option<i32> = sqlx
        ::query_scalar(
            "SELECT save_password FROM WebsitePreferences WHERE user_id = ? AND website = ?"
        )
        .bind(user_id)
        .bind(website)
        .fetch_optional(pool).await?;
    Ok(save_password.unwrap_or(1) != 0)
}

async fn process_websocket_message(
    pool: &Pool<Sqlite>,
    text: &str,
    ui_sender: &Sender<UiUpdate>,
    user_id: i32
) -> WebSocketResponse {
    println!("WebSocket recebeu: {}", text);
    match text {
        t if t.starts_with("PREF:") => {
            let parts: Vec<&str> = t[5..].split("|").collect();
            if parts.len() == 3 {
                match save_field_preference(pool, parts[0], parts[1], parts[2]).await {
                    Ok(_) =>
                        WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: Vec::new(),
                            save_allowed: Some(
                                get_website_preference(pool, user_id, parts[0]).await.unwrap_or(
                                    true
                                )
                            ),
                            error: None,
                            multiple_accounts: None,
                        },
                    Err(e) =>
                        WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: Vec::new(),
                            save_allowed: None,
                            error: Some(e.to_string()),
                            multiple_accounts: None,
                        },
                }
            } else {
                WebSocketResponse {
                    password: None,
                    username_email: None,
                    preferences: Vec::new(),
                    save_allowed: None,
                    error: Some(format!("Formato Inválido: {}", parts.len())),
                    multiple_accounts: None,
                }
            }
        }
        t if t.starts_with("GET_FIELD:") => {
            let parts: Vec<&str> = t[10..].split("|").collect();
            if parts.len() == 2 {
                let hostname = parts[0];
                let role = parts[1];
                match retrieve_field_data(pool, user_id, hostname, role).await {
                    Ok((value, selector)) => {
                        let mut response = WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: vec![FieldPreference {
                                selector,
                                role: role.to_string(),
                            }],
                            save_allowed: Some(
                                get_website_preference(pool, user_id, hostname).await.unwrap_or(
                                    true
                                )
                            ),
                            error: None,
                            multiple_accounts: None,
                        };
                        if role == "password" {
                            response.password = value;
                        } else if role == "username" {
                            response.username_email = value;
                        }
                        response
                    }
                    Err(e) =>
                        WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: Vec::new(),
                            save_allowed: None,
                            error: Some(e.to_string()),
                            multiple_accounts: None,
                        },
                }
            } else {
                WebSocketResponse {
                    password: None,
                    username_email: None,
                    preferences: Vec::new(),
                    save_allowed: None,
                    error: Some(format!("Formato Inválido: {}", parts.len())),
                    multiple_accounts: None,
                }
            }
        }
        t if t.starts_with("SET_WEBSITE_PREF:") => {
            let parts: Vec<&str> = t[17..].split("|").collect();
            if parts.len() == 2 {
                let website = parts[0];
                let save_password = parts[1] == "1";
                match save_website_preference(pool, user_id, website, save_password).await {
                    Ok(_) =>
                        WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: Vec::new(),
                            save_allowed: Some(save_password),
                            error: None,
                            multiple_accounts: None,
                        },
                    Err(e) =>
                        WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: Vec::new(),
                            save_allowed: None,
                            error: Some(e.to_string()),
                            multiple_accounts: None,
                        },
                }
            } else {
                WebSocketResponse {
                    password: None,
                    username_email: None,
                    preferences: Vec::new(),
                    save_allowed: None,
                    error: Some(format!("Formato Inválido: {}", parts.len())),
                    multiple_accounts: None,
                }
            }
        }
        t if t.starts_with("ADD_PASSWORD|") => {
            let parts: Vec<&str> = t[13..].split("|").collect();
            println!("ADD_PASSWORD parts: {:?}", parts);
            if parts.len() == 5 {
                let website = parts[0];
                println!("Processing ADD_PASSWORD for website: {}", website);
                if !get_website_preference(pool, user_id, website).await.unwrap_or(true) {
                    let _ = ui_sender.send(
                        UiUpdate::Error("Guardar passwords desligado para este website".to_string())
                    ).await;
                    return WebSocketResponse {
                        password: None,
                        username_email: None,
                        preferences: Vec::new(),
                        save_allowed: Some(false),
                        error: Some("Guardar passwords desligado para este website".to_string()),
                        multiple_accounts: None,
                    };
                }
                match
                    add_password_with_selectors(
                        pool,
                        user_id,
                        website,
                        parts[1],
                        parts[2],
                        parts[3],
                        parts[4]
                    ).await
                {
                    Ok(()) => {
                        println!("Password recebida com sucesso, a atualizar ui");
                        let pool_clone = pool.clone();
                        let ui_sender_clone = ui_sender.clone();
                        tokio::spawn(async move {
                            let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                            let passwords = read_stored_passwords(
                                &pool_clone,
                                user_id,
                                key
                            ).await.unwrap_or_default();
                            let _ = ui_sender_clone
                                .send(UiUpdate::AddPasswordSuccess(passwords)).await
                                .map_err(|e| println!("Falha na atualização da ui {}", e));
                        });
                        WebSocketResponse {
                            password: Some(parts[2].to_string()),
                            username_email: Some(parts[1].to_string()),
                            preferences: vec![
                                FieldPreference {
                                    selector: parts[3].to_string(),
                                    role: "Username".to_string(),
                                },
                                FieldPreference {
                                    selector: parts[4].to_string(),
                                    role: "Password".to_string(),
                                }
                            ],
                            save_allowed: Some(true),
                            error: None,
                            multiple_accounts: None,
                        }
                    }
                    Err(e) => {
                        let error_message = e.to_string();
                        println!("Falha em adicionar password: {}", error_message);
                        let _ = ui_sender.send(UiUpdate::Error(error_message.clone())).await;
                        WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: Vec::new(),
                            save_allowed: None,
                            error: Some(error_message),
                            multiple_accounts: None,
                        }
                    }
                }
            } else {
                let error_message = format!("Formato Inválido {}", parts.len());
                println!("{}", error_message);
                let _ = ui_sender.send(UiUpdate::Error(error_message.clone())).await;
                WebSocketResponse {
                    password: None,
                    username_email: None,
                    preferences: Vec::new(),
                    save_allowed: None,
                    error: Some(error_message),
                    multiple_accounts: None,
                }
            }
        }
        website => {
            println!("A processar autofill para: {}", website);
            match retrieve_password_and_prefs(pool, user_id, website).await {
                Ok(credentials) => {
                    println!("Informação passada: {:?}", credentials);
                    if credentials.is_empty() {
                        return WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: Vec::new(),
                            save_allowed: Some(
                                get_website_preference(pool, user_id, website).await.unwrap_or(true)
                            ),
                            error: None,
                            multiple_accounts: None,
                        };
                    }
                    let prefs = credentials[0].2.clone();
                    if credentials.len() == 1 {
                        let (password_opt, username_opt, _) = &credentials[0];
                        WebSocketResponse {
                            password: password_opt.clone(),
                            username_email: username_opt.clone(),
                            preferences: prefs,
                            save_allowed: Some(
                                get_website_preference(pool, user_id, website).await.unwrap_or(true)
                            ),
                            error: None,
                            multiple_accounts: None,
                        }
                    } else {
                        WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: prefs,
                            save_allowed: Some(
                                get_website_preference(pool, user_id, website).await.unwrap_or(true)
                            ),
                            error: None,
                            multiple_accounts: Some(
                                credentials
                                    .into_iter()
                                    .map(|(p, u, _)| (p.unwrap_or_default(), u.unwrap_or_default()))
                                    .collect()
                            ),
                        }
                    }
                }
                Err(e) => {
                    let error_message = e.to_string();
                    println!("Erro de request: {}", error_message);
                    let _ = ui_sender.send(UiUpdate::Error(error_message.clone())).await;
                    WebSocketResponse {
                        password: None,
                        username_email: None,
                        preferences: Vec::new(),
                        save_allowed: None,
                        error: Some(error_message),
                        multiple_accounts: None,
                    }
                }
            }
        }
    }
}

async fn retrieve_field_data(
    pool: &Pool<Sqlite>,
    user_id: i32,
    website: &str,
    role: &str
) -> Result<(Option<String>, String)> {
    let selector: String = sqlx
        ::query_scalar("SELECT selector FROM FieldPreferences WHERE website = ? AND role = ?")
        .bind(website)
        .bind(role)
        .fetch_optional(pool).await?
        .ok_or_else(|| anyhow!("No selector found for role {} on website {}", role, website))?;

    let value: Option<String> = if role == "password" {
        retrieve_password(pool, user_id, website).await?
    } else {
        sqlx
            ::query_scalar("SELECT username_email FROM Passwords WHERE user_id = ? AND website = ?")
            .bind(user_id)
            .bind(website)
            .fetch_optional(pool).await?
    };
    Ok((value, selector))
}

async fn retrieve_password_and_prefs(
    pool: &Pool<Sqlite>,
    user_id: i32,
    website: &str
) -> Result<Vec<(Option<String>, Option<String>, Vec<FieldPreference>)>> {
    let key = ENCRYPTION_KEY.lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Encryption key not set"))?;
    let rows = sqlx
        ::query_as::<_, (String, Vec<u8>)>(
            "SELECT username_email, password FROM Passwords WHERE user_id = ? AND website = ?"
        )
        .bind(user_id)
        .bind(website)
        .fetch_all(pool).await?;

    let mut credentials = Vec::new();
    for (username_email, encrypted_password) in rows {
        let decrypted_password = decrypt(&encrypted_password, &key)?;
        let decrypted_password_str = String::from_utf8(decrypted_password)?;
        let prefs = get_field_preferences(pool, website).await?;
        credentials.push((Some(decrypted_password_str), Some(username_email), prefs));
    }

    Ok(credentials)
}

async fn save_field_preference(
    pool: &Pool<Sqlite>,
    website: &str,
    selector: &str,
    role: &str
) -> Result<()> {
    if role != "Username" && role != "Password" {
        return Err(anyhow!("Invalid role: {}", role));
    }
    sqlx
        ::query(
            "INSERT OR REPLACE INTO FieldPreferences (website, selector, role) VALUES (?, ?, ?)"
        )
        .bind(website)
        .bind(selector)
        .bind(role)
        .execute(pool).await?;
    println!("Saved preference: website={}, selector={}, role={}", website, selector, role);
    Ok(())
}

async fn get_field_preferences(pool: &Pool<Sqlite>, website: &str) -> Result<Vec<FieldPreference>> {
    let rows = sqlx
        ::query_as::<_, FieldPreference>(
            "SELECT selector, role FROM FieldPreferences WHERE website = ?"
        )
        .bind(website)
        .fetch_all(pool).await?;
    Ok(rows)
}

async fn retrieve_password(
    pool: &Pool<Sqlite>,
    user_id: i32,
    website: &str
) -> Result<Option<String>> {
    let key = ENCRYPTION_KEY.lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Encryption key not set"))?;
    let encrypted_password: Option<Vec<u8>> = sqlx
        ::query_scalar("SELECT password FROM Passwords WHERE user_id = ? AND website = ?")
        .bind(user_id)
        .bind(website)
        .fetch_optional(pool).await?;
    Ok(
        encrypted_password.map(|ep|
            decrypt_password(&ep, &key).unwrap_or("Decryption failed".to_string())
        )
    )
}

async fn add_password_with_selectors(
    pool: &Pool<Sqlite>,
    user_id: i32,
    website: &str,
    username_email: &str,
    password: &str,
    username_selector: &str,
    password_selector: &str
) -> Result<()> {
    let key = ENCRYPTION_KEY.lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Chave de encriptção não definida={}", user_id))?;
    let encrypted_password = encrypt(password.as_bytes(), &key)?;

    let mut tx = pool.begin().await?;
    let existing_id: Option<i32> = sqlx
        ::query_scalar(
            "SELECT id FROM Passwords WHERE user_id = ? AND website = ? AND username_email = ?"
        )
        .bind(user_id)
        .bind(website)
        .bind(username_email)
        .fetch_optional(&mut *tx).await?;

    if let Some(id) = existing_id {
        sqlx
            ::query("UPDATE Passwords SET password = ? WHERE id = ?")
            .bind(&encrypted_password)
            .bind(id)
            .execute(&mut *tx).await?;
    } else {
        sqlx
            ::query(
                "INSERT INTO Passwords (user_id, website, username_email, password) VALUES (?, ?, ?, ?)"
            )
            .bind(user_id)
            .bind(website)
            .bind(username_email)
            .bind(&encrypted_password)
            .execute(&mut *tx).await?;
    }

    for (selector, role) in [
        (username_selector, "Username"),
        (password_selector, "Password"),
    ] {
        sqlx
            ::query(
                "INSERT OR REPLACE INTO FieldPreferences (website, selector, role) VALUES (?, ?, ?)"
            )
            .bind(website)
            .bind(selector)
            .bind(role)
            .execute(&mut *tx).await?;
    }

    tx.commit().await?;
    Ok(())
}

fn spawn_ui_update_handler(
    weak_window: Weak<BlackSquareWindow>,
    mut ui_receiver: Receiver<UiUpdate>
) {
    tokio::spawn(async move {
        while let Some(update) = ui_receiver.recv().await {
            slint
                ::invoke_from_event_loop({
                    let weak_window = weak_window.clone();
                    move || {
                        if let Some(window) = weak_window.upgrade() {
                            match update {
                                UiUpdate::AddPasswordSuccess(passwords) => {
                                    window.set_message(
                                        "✅ Password adicionada com sucesso!".into()
                                    );
                                    window.set_password_entries(
                                        ModelRc::new(VecModel::from(passwords))
                                    );
                                }
                                UiUpdate::Error(msg) =>
                                    window.set_message(format!("❌ {}", msg).into()),
                            }
                        }
                    }
                })
                .expect("Failed to invoke from event loop");
        }
    });
}

fn setup_password_handlers(
    black_square_window: &BlackSquareWindow,
    pool: &Pool<Sqlite>,
    user_id: i32,
    db_path: PathBuf,
    masterkey_path: PathBuf
) {
    let black_weak = black_square_window.as_weak();
    let pool = pool.clone();

    black_square_window.on_save_password({
        let black_weak = black_weak.clone();
        let pool = pool.clone();
        move || {
            let window = black_weak.upgrade().unwrap();
            let (website, username_email, password) = (
                window.get_selected_website().to_string(),
                window.get_selected_username_email().to_string(),
                window.get_selected_password().to_string(),
            );
            if website.is_empty() || username_email.is_empty() || password.is_empty() {
                window.set_message("Todos os campos são necessários".into());
                return;
            }

            slint
                ::spawn_local({
                    let black_weak = black_weak.clone();
                    let pool = pool.clone();
                    async move {
                        let result = if window.get_isAddMode() {
                            add_password(&pool, user_id, &website, &username_email, &password).await
                        } else {
                            update_password(
                                &pool,
                                window.get_id(),
                                user_id,
                                &website,
                                &username_email,
                                &password
                            ).await
                        };
                        let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                        let passwords = read_stored_passwords(
                            &pool,
                            user_id,
                            key
                        ).await.unwrap_or_default();
                        slint
                            ::invoke_from_event_loop(move || {
                                if let Some(window) = black_weak.upgrade() {
                                    match result {
                                        Ok(_) => {
                                            window.set_message(
                                                (
                                                    if window.get_isAddMode() {
                                                        "Password adicionada com sucesso!"
                                                    } else {
                                                        "Password atualizada com sucesso!"
                                                    }
                                                ).into()
                                            );
                                            window.set_password_entries(
                                                ModelRc::new(VecModel::from(passwords))
                                            );
                                        }
                                        Err(e) =>
                                            window.set_message(format!("Error: {}", e).into()),
                                    }
                                }
                            })
                            .unwrap();
                    }
                })
                .unwrap();
        }
    });

    black_square_window.on_websocket({
        let black_weak = black_weak.clone();
        let pool = pool.clone();
        move |enabled| {
            let window = black_weak.upgrade().unwrap();
            if enabled {
                let (ui_sender, ui_receiver) = channel::<UiUpdate>(100);
                let handle = tokio::spawn(start_websocket_server(pool.clone(), ui_sender, user_id));
                *WEBSOCKET_TASK.lock().unwrap() = Some(handle);
                spawn_ui_update_handler(window.as_weak(), ui_receiver);
                window.set_message("✅ Websocket Iniciado!".into());
                window.set_websocket_enabled(true);
            } else {
                if let Some(shutdown_tx) = WEBSOCKET_SHUTDOWN.lock().unwrap().as_ref() {
                    let _ = shutdown_tx.send(true);
                    if let Some(handle) = WEBSOCKET_TASK.lock().unwrap().take() {
                        handle.abort();
                        slint
                            ::spawn_local(async move {
                                if handle.await.is_ok() {
                                    // Error at line 769
                                    println!("WebSocket task completed after abort");
                                }
                            })
                            .unwrap();
                        window.set_message("✅ WebSocket foi parado.".into());
                    }
                } else {
                    window.set_message("❌ Sem websocket para parar.".into());
                }
                window.set_websocket_enabled(false);
                *WEBSOCKET_SHUTDOWN.lock().unwrap() = None;
            }
        }
    });

    setup_export_handler(black_square_window, db_path.clone(), masterkey_path.clone());

    black_square_window.on_edit({
        let black_weak = black_weak.clone();
        let pool = pool.clone();
        move |id, website, username_email, password| {
            let window = black_weak.upgrade().unwrap();
            let (website, username_email, password) = (
                website.to_string(),
                username_email.to_string(),
                password.to_string(),
            );
            if website.is_empty() || username_email.is_empty() || password.is_empty() {
                window.set_message("Todos os campos precisam de ser preenchidos.".into());
                return;
            }

            slint
                ::spawn_local({
                    let black_weak = black_weak.clone();
                    let pool = pool.clone();
                    async move {
                        let result = update_password(
                            &pool,
                            id,
                            user_id,
                            &website,
                            &username_email,
                            &password
                        ).await;
                        let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                        let passwords = read_stored_passwords(
                            &pool,
                            user_id,
                            key
                        ).await.unwrap_or_default();
                        slint
                            ::invoke_from_event_loop(move || {
                                if let Some(window) = black_weak.upgrade() {
                                    match result {
                                        Ok(_) => {
                                            window.set_message(
                                                "✅ Password atualizada com sucesso!".into()
                                            );
                                            window.set_password_entries(
                                                ModelRc::new(VecModel::from(passwords))
                                            );
                                        }
                                        Err(e) =>
                                            window.set_message(
                                                format!("❌ Erro ao atualizar a password: {}", e).into()
                                            ),
                                    }
                                }
                            })
                            .unwrap();
                    }
                })
                .unwrap();
        }
    });

    black_square_window.on_deletePassword({
        let black_weak = black_weak.clone();
        let pool = pool.clone();
        move |id| {
            slint
                ::spawn_local({
                    let black_weak = black_weak.clone();
                    let pool = pool.clone();
                    async move {
                        let result = delete_password(&pool, id, user_id).await;
                        let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                        let passwords = read_stored_passwords(
                            &pool,
                            user_id,
                            key
                        ).await.unwrap_or_default();
                        slint
                            ::invoke_from_event_loop(move || {
                                if let Some(window) = black_weak.upgrade() {
                                    match result {
                                        Ok(_) => {
                                            window.set_message("✅ Password deleteda !".into());
                                            window.set_password_entries(
                                                ModelRc::new(VecModel::from(passwords))
                                            );
                                        }
                                        Err(e) =>
                                            window.set_message(
                                                format!("❌ Erro ao deletar password: {}", e).into()
                                            ),
                                    }
                                }
                            })
                            .unwrap();
                    }
                })
                .unwrap();
        }
    });

    black_square_window.on_toggle_autostart({
        let black_weak = black_weak.clone();
        move |enabled| {
            let app_name = "EZPass".to_string(); // Clone to move into async block
            let exe_path = std::env::current_exe().unwrap().to_str().unwrap().to_string(); // Clone to move into async block

            slint
                ::spawn_local({
                    let window_weak = black_weak.clone();
                    async move {
                        if enabled {
                            match add_to_startup(&app_name, &exe_path).await {
                                Err(e) => {
                                    if let Some(window) = window_weak.upgrade() {
                                        window.set_message(
                                            format!("❌ Falha ao ativar autostart: {}", e).into()
                                        );
                                    }
                                }
                                Ok(()) => {
                                    if let Some(window) = window_weak.upgrade() {
                                        window.set_message("✅ Autostart ativado".into());
                                    }
                                }
                            }
                        } else {
                            match remove_from_startup(&app_name).await {
                                Err(e) => {
                                    if let Some(window) = window_weak.upgrade() {
                                        window.set_message(
                                            format!("❌ Falha ao desativar autostart: {}", e).into()
                                        );
                                    }
                                }
                                Ok(()) => {
                                    if let Some(window) = window_weak.upgrade() {
                                        window.set_message("✅ Autostart desativado".into());
                                    }
                                }
                            }
                        }
                    }
                })
                .unwrap(); // Spawn the async task
        }
    });
}

fn hash_password(password: &str, salt: &SaltString) -> Result<String> {
    Ok(
        Argon2::default()
            .hash_password(password.as_bytes(), salt)
            .map_err(|e| anyhow!(e))?
            .to_string()
    )
}

fn derive_key(password: &str, salt: &str) -> Result<Vec<u8>> {
    let salt = SaltString::from_b64(salt).map_err(|e| anyhow!("Invalid salt: {}", e))?;
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt).map_err(|e| anyhow!(e))?;
    Ok(
        password_hash.hash
            .ok_or_else(|| anyhow!("No hash output"))?
            .as_bytes()
            .to_vec()
    )
}

fn encrypt_password(plaintext: &str, key: &[u8]) -> Result<Vec<u8>> {
    encrypt(plaintext.as_bytes(), key).map_err(|e| anyhow!("Encryption failed: {}", e))
}

fn decrypt_password(encrypted_data: &[u8], key: &[u8]) -> Result<String> {
    let plaintext = decrypt(encrypted_data, key)?;
    String::from_utf8(plaintext).map_err(|e| anyhow!("Invalid UTF-8 in decrypted data: {}", e))
}

async fn add_password(
    pool: &Pool<Sqlite>,
    user_id: i32,
    website: &str,
    username_email: &str,
    password: &str
) -> Result<()> {
    let key = ENCRYPTION_KEY.lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Encryption key not set"))?;
    let encrypted_password = encrypt_password(password, &key)?;
    sqlx
        ::query(
            "INSERT INTO Passwords (user_id, website, username_email, password) VALUES (?, ?, ?, ?)"
        )
        .bind(user_id)
        .bind(website)
        .bind(username_email)
        .bind(&encrypted_password)
        .execute(pool).await?;
    Ok(())
}

async fn update_password(
    pool: &Pool<Sqlite>,
    id: i32,
    user_id: i32,
    website: &str,
    username_email: &str,
    password: &str
) -> Result<()> {
    let key = ENCRYPTION_KEY.lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Encryption key not set"))?;
    let encrypted_password = encrypt_password(password, &key)?;
    let rows_affected = sqlx
        ::query(
            "UPDATE Passwords SET website = ?, username_email = ?, password = ? WHERE id = ? AND user_id = ?"
        )
        .bind(website)
        .bind(username_email)
        .bind(&encrypted_password)
        .bind(id)
        .bind(user_id)
        .execute(pool).await?
        .rows_affected();
    if rows_affected == 0 {
        return Err(anyhow!("No matching record found to update"));
    }
    Ok(())
}

async fn delete_password(pool: &Pool<Sqlite>, id: i32, user_id: i32) -> Result<()> {
    let rows_affected = sqlx
        ::query("DELETE FROM Passwords WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user_id)
        .execute(pool).await?
        .rows_affected();
    if rows_affected == 0 {
        return Err(anyhow!("No matching record found to delete"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn add_to_startup(app_name: &str, app_path: &str) -> Result<()> {
    use winreg::RegKey;
    use winreg::enums::*;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey_with_flags(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        KEY_SET_VALUE
    )?;
    run_key.set_value(app_name, &app_path)?;
    Ok(())
}

#[cfg(target_os = "windows")]
async fn remove_from_startup(app_name: &str) -> Result<()> {
    use winreg::RegKey;
    use winreg::enums::*;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey_with_flags(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        KEY_SET_VALUE
    )?;
    run_key.delete_value(app_name)?;
    Ok(())
}

#[cfg(target_os = "windows")]
async fn is_in_startup(app_name: &str) -> Result<bool> {
    use winreg::RegKey;
    use winreg::enums::*;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")?;
    Ok(run_key.get_value::<String, _>(app_name).is_ok())
}

#[cfg(target_os = "linux")]
async fn add_to_startup(app_name: &str, app_path: &str) -> Result<()> {
    let desktop_content = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={}\n\
         Exec={}\n\
         Hidden=false\n\
         NoDisplay=false\n\
         X-GNOME-Autostart-enabled=true",
        app_name,
        app_path
    );
    let autostart_dir = dirs
        ::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("autostart");
    tokio::fs::create_dir_all(&autostart_dir).await?;
    tokio::fs::write(autostart_dir.join(format!("{}.desktop", app_name)), desktop_content).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn remove_from_startup(app_name: &str) -> Result<()> {
    let autostart_dir = dirs
        ::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("autostart");
    let path = autostart_dir.join(format!("{}.desktop", app_name));
    if path.exists() {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn is_in_startup(app_name: &str) -> Result<bool> {
    let autostart_dir = dirs
        ::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("autostart");
    Ok(autostart_dir.join(format!("{}.desktop", app_name)).exists())
}

#[cfg(target_os = "macos")]
async fn add_to_startup(app_name: &str, app_path: &str) -> Result<()> {
    let plist_content = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
             <key>Label</key>\n\
             <string>{}</string>\n\
             <key>ProgramArguments</key>\n\
             <array>\n\
                 <string>{}</string>\n\
             </array>\n\
             <key>RunAtLoad</key>\n\
             <true/>\n\
         </dict>\n\
         </plist>",
        app_name,
        app_path
    );
    let launch_agents_dir = dirs
        ::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/LaunchAgents");
    tokio::fs::create_dir_all(&launch_agents_dir).block_on()?;
    tokio::fs
        ::write(launch_agents_dir.join(format!("com.{}.plist", app_name)), plist_content)
        .block_on()?;
    Ok(())
}

#[cfg(target_os = "macos")]
async fn remove_from_startup(app_name: &str) -> Result<()> {
    let launch_agents_dir = dirs
        ::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/LaunchAgents");
    let path = launch_agents_dir.join(format!("com.{}.plist", app_name));
    if path.exists() {
        tokio::fs::remove_file(path).block_on()?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn is_in_startup(app_name: &str) -> Result<bool> {
    let launch_agents_dir = dirs
        ::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/LaunchAgents");
    Ok(launch_agents_dir.join(format!("com.{}.plist", app_name)).exists())
}

fn handle_logout(ui: Arc<LoginWindow>, black_square_window: Arc<BlackSquareWindow>) {
    if let Some(handle) = WEBSOCKET_TASK.lock().unwrap().take() {
        handle.abort();
    }
    *ENCRYPTION_KEY.lock().unwrap() = None;
    black_square_window.set_password_entries(ModelRc::new(VecModel::from(Vec::new())));
    ui.set_message("".into());
    ui.show().unwrap();
    black_square_window.hide().unwrap();
}

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::env;
        if let Ok(session_type) = env::var("XDG_SESSION_TYPE") {
            match session_type.as_str() {
                "wayland" => env::set_var("WINIT_UNIX_BACKEND", "wayland"),
                "x11" => env::set_var("WINIT_UNIX_BACKEND", "x11"),
                _ =>
                    println!("Unknown session type: {}, letting winit choose the backend", session_type),
            }
        } else {
            println!("XDG_SESSION_TYPE not set, letting winit choose the backend");
        }
    }
    let ui = Arc::new(LoginWindow::new()?);
    let black_square_window = Arc::new(BlackSquareWindow::new()?);

    let ui_clone = Arc::clone(&ui);
    let black_clone = Arc::clone(&black_square_window);

    black_square_window.on_logout({
        let ui_clone = ui_clone.clone();
        let black_clone = black_clone.clone();
        move || handle_logout(ui_clone.clone(), black_clone.clone())
    });

    setup_login_handler(&ui, &black_square_window);
    setup_register_handler(ui.clone()).await; // Await and propagate errors
    setup_import_handler(ui.clone(), black_square_window.clone()).await; // Await and propagate errors

    let app_name = "EZPass";
    let app_path = std::env
        ::current_exe()?
        .to_str()
        .ok_or_else(|| anyhow!("Failed to get executable path"))?
        .to_string();
    if let Ok(is_enabled) = is_in_startup(app_name).await {
        // Await the Future
        black_square_window.set_autostart_enabled(is_enabled);
    } else if add_to_startup(app_name, &app_path).await.is_ok() {
        // Await the Future
        black_square_window.set_autostart_enabled(true);
    }

    ui.show()?;
    slint::run_event_loop()?;
    Ok(())
}
