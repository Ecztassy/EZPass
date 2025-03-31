#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use std::sync::Arc;
use rand::RngCore;
use rfd::AsyncFileDialog;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use slint::{ModelRc, VecModel, Weak};
use rand::rngs::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use std::fs;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures_util::{StreamExt, SinkExt};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde_derive::{Serialize, Deserialize};
use serde_json;
use tokio::sync::mpsc::{channel, Sender, Receiver};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use simple_crypt::{encrypt, decrypt};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use hex;
use dirs;

slint::include_modules!();

static WEBSOCKET_TASK: Lazy<Mutex<Option<tokio::task::JoinHandle<()>>>> = Lazy::new(|| Mutex::new(None));
static WEBSOCKET_SHUTDOWN: Lazy<Mutex<Option<watch::Sender<bool>>>> = Lazy::new(|| Mutex::new(None));
static ENCRYPTION_KEY: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

const DATABASE_DIR: &str = "databases";

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

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FieldPreference {
    selector: String,
    role: String,
}

fn get_database_path(name: &str) -> PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("EZPass")
        .join(DATABASE_DIR);
    if !dir.exists() {
        fs::create_dir_all(&dir).expect("Falha ao obter o diretório das DB.");
    }
    dir.join(format!("{}.db", name))
}

fn load_config() -> Result<Config> {
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("EZPass");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.json");
    if config_path.exists() {
        let config_str = fs::read_to_string(&config_path)?;
        Ok(serde_json::from_str(&config_str)?)
    } else {
        Ok(Config { databases: Vec::with_capacity(4) })
    }
}

fn save_config(config: &Config) -> Result<()> {
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("EZPass");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.json");
    let config_str = serde_json::to_string_pretty(config)?;
    fs::write(&config_path, config_str.as_bytes())?;
    Ok(())
}

async fn setup_database(db_path: &Path) -> Result<Arc<Pool<SqliteConnectionManager>>> {
    let manager = SqliteConnectionManager::file(db_path);
    let pool = Arc::new(Pool::builder().max_size(5).build(manager)?);

    tokio::task::spawn_blocking({
        let pool = Arc::clone(&pool);
        move || {
            let conn = pool.get()?;
            conn.execute_batch(
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
            )?;
            Ok::<_, anyhow::Error>(())
        }
    }).await??;

    Ok(pool)
}

async fn import_database(db_file: &Path, masterkey_file: &Path, username: Option<&str>) -> Result<(i32, Arc<Pool<SqliteConnectionManager>>)> {
    let mut config = load_config()?;
    let name = db_file.file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("Invalid database name"))?;

    // Get unique destination path
    let mut db_path = get_database_path(name);
    let mut masterkey_path = db_path.with_extension("masterkey");
    
    // If a database with this name exists, create a unique name
    let mut counter = 1;
    let base_name = name.to_string();
    while config.databases.iter().any(|db| db.db_path == db_path) {
        let new_name = format!("{}_{}", base_name, counter);
        db_path = get_database_path(&new_name);
        masterkey_path = db_path.with_extension("masterkey");
        counter += 1;
    }

    // Copy the files to the new location
    fs::copy(db_file, &db_path)?;
    fs::copy(masterkey_file, &masterkey_path)?;

    // Setup database connection
    let pool = setup_database(&db_path).await?;

    // Verify the database is valid by checking if we can read from it
    let conn = pool.get()?;
    let masterkey_hex = fs::read_to_string(&masterkey_path)?;
    let masterkey = hex::decode(&masterkey_hex)
        .map_err(|e| anyhow!("Invalid masterkey file: {}", e))?;

    let username_to_check = username.unwrap_or_else(|| "default"); // Fallback if no username provided
    let mut stmt = conn.prepare(
        "SELECT id, enc_key_encrypted_with_masterkey, enc_key_hash FROM users WHERE username = ?"
    )?;
    
    let (user_id, enc_key_encrypted, enc_key_hash) = stmt.query_row(params![username_to_check], |row| {
        Ok((row.get::<_, i32>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, String>(2)?))
    }).optional()?.ok_or_else(|| anyhow!("User not found in imported database"))?;

    // Verify masterkey
    let decrypted_key = decrypt(&enc_key_encrypted, &masterkey)?;
    let mut hasher = Sha256::default();
    hasher.update(&decrypted_key);
    if hex::encode(hasher.finalize()) != enc_key_hash {
        fs::remove_file(&db_path)?;
        fs::remove_file(&masterkey_path)?;
        return Err(anyhow!("Masterkey does not match the database"));
    }

    // Update config only if verification succeeds
    config.databases.push(DatabaseConfig {
        name: db_path.file_stem().unwrap().to_str().unwrap().to_string(),
        db_path: db_path.clone(),
        masterkey_path: masterkey_path.clone(),
    });
    save_config(&config)?;

    // Set encryption key and return pool with user_id for immediate use
    *ENCRYPTION_KEY.lock().unwrap() = Some(decrypted_key);
    Ok((user_id, pool))
}

async fn register_user(db_path: &Path, username: String, password: String) -> Result<Arc<Pool<SqliteConnectionManager>>> {
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
    export_hash_to_file(&hex::encode(&masterkey), &masterkey_path).await?;
    
    let pool = setup_database(db_path).await?;
    let conn = pool.get()?;
    conn.execute(
        "INSERT INTO users (username, password, salt, enc_key_encrypted_with_pwd, enc_key_encrypted_with_masterkey, enc_key_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![&username, &hashed_password, salt.as_str(), &enc_key_encrypted_with_pwd, &enc_key_encrypted_with_masterkey, &enc_key_hash],
    )?;

    *ENCRYPTION_KEY.lock().unwrap() = Some(enc_key);
    Ok(pool)
}

async fn check_login(
    db_path: &Path,
    username: &str,
    password: &str,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<(bool, i32, Arc<Pool<SqliteConnectionManager>>)> {
    let conn = setup_database(db_path).await?;
    let conn_inner = conn.get()?;
    let mut stmt = conn_inner.prepare("SELECT id, password, salt, enc_key_encrypted_with_pwd, enc_key_hash FROM users WHERE username = ?")?;
    let row = stmt.query_row(params![username], |row| {
        Ok((
            row.get::<_, i32>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, String>(4)?
        ))
    }).optional()?;
    
    if let Some((user_id, stored_password, salt, enc_key_encrypted_with_pwd, enc_key_hash)) = row {
        let parsed_hash = PasswordHash::new(&stored_password).map_err(|e| anyhow!(e))?;
        if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok() {
            let pwd_key = derive_key(password, &salt)?;
            let enc_key_candidate = decrypt(&enc_key_encrypted_with_pwd, &pwd_key)?;
            let mut hasher = Sha256::default();
            hasher.update(&enc_key_candidate);
            if hex::encode(hasher.finalize()) == enc_key_hash {
                *ENCRYPTION_KEY.lock().unwrap() = Some(enc_key_candidate.clone());
                let passwords = read_stored_passwords(&conn, user_id, enc_key_candidate).await?;
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
                return Ok((true, user_id, conn));
            }
        }
    }
    Ok((false, 0, conn))
}

async fn check_masterkey_login(
    db_path: &Path,
    masterkey_path: &Path,
    username: &str,
    black_square_window_handle: Weak<BlackSquareWindow>,
) -> Result<(bool, i32, Arc<Pool<SqliteConnectionManager>>)> {
    let masterkey_hex = fs::read_to_string(masterkey_path)?;
    let masterkey = hex::decode(&masterkey_hex).map_err(|e| anyhow!("Arquivo masterkey inválido: {}", e))?;
    let conn = setup_database(db_path).await?;
    let conn_inner = conn.get()?;
    let mut stmt = conn_inner.prepare("SELECT id, enc_key_encrypted_with_masterkey, enc_key_hash FROM users WHERE username = ?")?;
    let row = stmt.query_row(params![username], |row| {
        Ok((row.get::<_, i32>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, String>(2)?))
    }).optional()?;
    
    if let Some((user_id, enc_key_encrypted_with_masterkey, enc_key_hash)) = row {
        let enc_key_candidate = decrypt(&enc_key_encrypted_with_masterkey, &masterkey)?;
        let mut hasher = Sha256::default();
        hasher.update(&enc_key_candidate);
        if hex::encode(hasher.finalize()) == enc_key_hash {
            *ENCRYPTION_KEY.lock().unwrap() = Some(enc_key_candidate.clone());
            let passwords = read_stored_passwords(&conn, user_id, enc_key_candidate).await?;
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
            return Ok((true, user_id, conn));
        }
    }
    Ok((false, 0, conn))
}

async fn read_stored_passwords(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    user_id: i32,
    key: Vec<u8>,
) -> Result<Vec<PasswordEntry>> {
    let conn = conn.get()?;
    let mut stmt = conn.prepare("SELECT id, website, username_email, password FROM Passwords WHERE user_id = ?1")?;
    let password_iter = stmt.query_map(params![user_id], |row| {
        let id: i32 = row.get(0)?;
        let website: String = row.get(1)?;
        let username_email: String = row.get(2)?;
        let encrypted_password: Vec<u8> = row.get(3)?;
        let password = decrypt_password(&encrypted_password, &key).unwrap_or_else(|e| format!("Formatação falhou {}", e));
        Ok(PasswordEntry {
            id,
            website: website.into(),
            username_email: username_email.into(),
            password: password.into(),
        })
    })?;
    let passwords = password_iter.collect::<Result<Vec<_>, _>>()?;
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
            let (username, password) = (ui.get_username().to_string(), ui.get_password().to_string());
            if username.is_empty() || password.is_empty() {
                ui.set_message("Por favor ensira o nome de utilizador e password.".into());
                return;
            }

            slint::spawn_local({
                let ui_weak = ui_weak.clone();
                let black_weak = black_weak.clone();
                async move {
                    let db_path = match AsyncFileDialog::new()
                        .set_title("Selecionar arquivo de DB.")
                        .pick_file()
                        .await {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint::invoke_from_event_loop(move || {
                                    ui_weak.upgrade().map(|ui| ui.set_message("Seleção cancelada".into()));
                                }).unwrap();
                                return;
                            }
                        };
                    let config = load_config().unwrap();
                    let masterkey_path = config.databases.iter()
                        .find(|db| db.db_path == db_path)
                        .map(|c| c.masterkey_path.clone())
                        .unwrap_or_else(|| db_path.with_extension("masterkey"));

                    let result = check_login(&db_path, &username, &password, black_weak.clone()).await;
                    slint::invoke_from_event_loop({
                        let ui_weak = ui_weak.clone();
                        let black_weak = black_weak.clone();
                        move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                match result {
                                    Ok((true, user_id, conn)) => {
                                        ui.set_message("Login bem-sucessido!".into());
                                        ui.set_username("".into());
                                        ui.set_password("".into());
                                        ui.hide().unwrap();
                                        if let Some(window) = black_weak.upgrade() {
                                            setup_password_handlers(&window, &conn, user_id, db_path, masterkey_path);
                                        }
                                    }
                                    Ok((false, _, _)) => ui.set_message("Utilizador e password inválida.".into()),
                                    Err(e) => ui.set_message(format!("Erro de login: {}", e).into()),
                                }
                            }
                        }
                    }).unwrap();
                }
            }).unwrap();
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

            slint::spawn_local({
                let ui_weak = ui_weak.clone();
                let black_weak = black_weak.clone();
                async move {
                    let db_path = match AsyncFileDialog::new()
                        .set_title("Selecionar arquivo de DB")
                        .pick_file()
                        .await {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint::invoke_from_event_loop(move || {
                                    ui_weak.upgrade().map(|ui| ui.set_message("Seleção cancelada".into()));
                                }).unwrap();
                                return;
                            }
                        };
                    let masterkey_path = match AsyncFileDialog::new()
                        .set_title("Selecionar chave")
                        .pick_file()
                        .await {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint::invoke_from_event_loop(move || {
                                    ui_weak.upgrade().map(|ui| ui.set_message("Seleção cancelada".into()));
                                }).unwrap();
                                return;
                            }
                        };

                    let result = check_masterkey_login(&db_path, &masterkey_path, &username, black_weak.clone()).await;
                    slint::invoke_from_event_loop({
                        let ui_weak = ui_weak.clone();
                        let black_weak = black_weak.clone();
                        move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                match result {
                                    Ok((true, user_id, conn)) => {
                                        ui.set_message("Login com a masterkey bem sucedida!".into());
                                        ui.hide().unwrap();
                                        if let Some(window) = black_weak.upgrade() {
                                            setup_password_handlers(&window, &conn, user_id, db_path, masterkey_path);
                                        }
                                    }
                                    Ok((false, _, _)) => ui.set_message("Masterkey inválida.".into()),
                                    Err(e) => ui.set_message(format!("Erro: {}", e).into()),
                                }
                            }
                        }
                    }).unwrap();
                }
            }).unwrap();
        }
    });
}

async fn setup_register_handler(ui: Arc<LoginWindow>) {
    let ui_weak = ui.as_weak();
    ui.on_register_clicked({
        let ui_weak = ui_weak.clone();
        move || {
            let ui = ui_weak.upgrade().unwrap();
            let (username, password) = (ui.get_username().to_string(), ui.get_password().to_string());
            if username.is_empty() || password.is_empty() {
                ui.set_message("Por favor insira utilizador e password.".into());
                return;
            }

            slint::spawn_local({
                let ui_weak = ui_weak.clone();
                async move {
                    let db_path = match AsyncFileDialog::new()
                        .set_file_name("Nova_database.db")
                        .save_file()
                        .await {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint::invoke_from_event_loop(move || {
                                    ui_weak.upgrade().map(|ui| ui.set_message("Falha na criação de database".into()));
                                }).unwrap();
                                return;
                            }
                        };
                    let db_name = db_path.file_stem().unwrap().to_str().unwrap().to_string();
                    let result = register_user(&db_path, username, password).await;
                    slint::invoke_from_event_loop({
                        let ui_weak = ui_weak.clone();
                        move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                match result {
                                    Ok(_conn) => {
                                        let mut config = load_config().unwrap();
                                        if !config.databases.iter().any(|db| db.db_path == db_path) {
                                            config.databases.push(DatabaseConfig {
                                                name: db_name,
                                                db_path: db_path.clone(),
                                                masterkey_path: db_path.with_extension("masterkey"),
                                            });
                                            save_config(&config).unwrap();
                                        }
                                        ui.set_message("Registro bem sucedido!".into());
                                        ui.set_username("".into());
                                        ui.set_password("".into());
                                    }
                                    Err(e) => ui.set_message(format!("Falha no registro: {}", e).into()),
                                }
                            }
                        }
                    }).unwrap();
                }
            }).unwrap();
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
            slint::spawn_local({
                let ui_weak = ui_weak.clone();
                let black_weak = black_weak.clone();
                async move {
                    let db_file = match AsyncFileDialog::new()
                        .set_title("Select database file to import:")
                        .add_filter("Database", &["db"])
                        .pick_file()
                        .await {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint::invoke_from_event_loop(move || {
                                    ui_weak.upgrade().map(|ui| ui.set_message("Database selection canceled".into()));
                                })?;
                                return Ok::<(), anyhow::Error>(());
                            }
                        };
                    let masterkey_file = match AsyncFileDialog::new()
                        .set_title("Select Masterkey File")
                        .add_filter("Masterkey File", &["masterkey"])
                        .pick_file()
                        .await {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint::invoke_from_event_loop(move || {
                                    ui_weak.upgrade().map(|ui| ui.set_message("Masterkey selection canceled.".into()));
                                })?;
                                return Ok(());
                            }
                        };

                    match import_database(&db_file, &masterkey_file, Some(&ui_weak.upgrade().unwrap().get_username().to_string())).await {
                        Ok((user_id, pool)) => {
                            let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                            let passwords = read_stored_passwords(&pool, user_id, key).await?;
                            
                            slint::invoke_from_event_loop({
                                let ui_weak = ui_weak.clone();
                                let black_weak = black_weak.clone();
                                move || {
                                    // Show the black square window first
                                    if let Some(window) = black_weak.upgrade() {
                                        window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                                        window.show().unwrap();
                                        setup_password_handlers(&window, &pool, user_id, db_file.clone(), masterkey_file.clone());
                                    }
                                    // Then hide the login window
                                    if let Some(ui) = ui_weak.upgrade() {
                                        ui.set_message("Database imported successfully!".into());
                                        ui.hide().unwrap();
                                    }
                                }
                            })?;
                        }
                        Err(e) => slint::invoke_from_event_loop(move || {
                            ui_weak.upgrade().map(|ui| ui.set_message(format!("Import failed: {}", e).into()));
                        })?,
                    }
                    Ok(())
                }
            }).unwrap();
        }
    });
}

fn setup_export_handler(black_square_window: &BlackSquareWindow, db_path: PathBuf, masterkey_path: PathBuf) {
    let black_weak = black_square_window.as_weak();
    black_square_window.on_export({
        let db_path = db_path.clone();
        let masterkey_path = masterkey_path.clone();
        move || {
            slint::spawn_local({
                let black_weak = black_weak.clone();
                let db_path = db_path.clone();
                let masterkey_path = masterkey_path.clone();
                async move {
                    let db_file = match AsyncFileDialog::new()
                        .set_file_name("exportada.db")
                        .save_file()
                        .await {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint::invoke_from_event_loop(move || {
                                    black_weak.upgrade().map(|w| w.set_message("Exportação da database cancelada.".into()));
                                }).unwrap();
                                return;
                            }
                        };
                    if let Err(e) = fs::copy(&db_path, &db_file) {
                        slint::invoke_from_event_loop(move || {
                            black_weak.upgrade().map(|w| w.set_message(format!("Exportação da database falhou. {}", e).into()));
                        }).unwrap();
                        return;
                    }
                    let masterkey_file = match AsyncFileDialog::new()
                        .set_file_name("exportada.masterkey")
                        .save_file()
                        .await {
                            Some(handle) => handle.path().to_path_buf(),
                            None => {
                                slint::invoke_from_event_loop(move || {
                                    black_weak.upgrade().map(|w| w.set_message("Exportação da masterkey cancelada".into()));
                                }).unwrap();
                                return;
                            }
                        };
                    match fs::copy(&masterkey_path, &masterkey_file) {
                        Ok(_) => slint::invoke_from_event_loop(move || {
                            black_weak.upgrade().map(|w| w.set_message("Database e masterkey exportadas com sucesso!".into()));
                        }),
                        Err(e) => slint::invoke_from_event_loop(move || {
                            black_weak.upgrade().map(|w| w.set_message(format!("Exportação da masterkey falhou: {}", e).into()));
                        }),
                    }.unwrap();
                }
            }).unwrap();
        }
    });
}

async fn start_websocket_server(
    conn: Arc<Pool<SqliteConnectionManager>>,
    ui_sender: Sender<UiUpdate>,
    user_id: i32,
) {
    println!("Iniciando websocket no 127.0.0.1:9001...");
    let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    *WEBSOCKET_SHUTDOWN.lock().unwrap() = Some(shutdown_tx);

    'websocket_loop: while let Ok((stream, _)) = tokio::select! {
        result = listener.accept() => result,
        _ = shutdown_rx.changed() => {
            if *shutdown_rx.borrow() {
                println!("Servidor websocket a desligar...");
                break 'websocket_loop;
            }
            println!("websocket recebeu pedido de desligar mas não terminou");
            continue 'websocket_loop;
        }
    } {
        let conn_clone = Arc::clone(&conn);
        let ui_sender_clone = ui_sender.clone();
        tokio::spawn(async move {
            if let Ok(ws_stream) = accept_async(stream).await {
                let (mut write, mut read) = ws_stream.split();
                while let Some(msg) = read.next().await {
                    if let Ok(Message::Text(text)) = msg {
                        let response = process_websocket_message(&conn_clone, &text, &ui_sender_clone, user_id).await;
                        let json_response = serde_json::to_string(&response).unwrap_or_else(|e| format!("{{\"error\":\"Erro de formatação: {}\"}}", e));
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

fn save_website_preference(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    user_id: i32,
    website: &str,
    save_password: bool,
) -> Result<()> {
    let conn = conn.get()?;
    conn.execute(
        "INSERT OR REPLACE INTO WebsitePreferences (user_id, website, save_password) VALUES (?1, ?2, ?3)",
        params![user_id, website, save_password as i32],
    )?;
    Ok(())
}

fn get_website_preference(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    user_id: i32,
    website: &str,
) -> Result<bool> {
    let conn = conn.get()?;
    let save_password: Option<i32> = conn
        .query_row(
            "SELECT save_password FROM WebsitePreferences WHERE user_id = ?1 AND website = ?2",
            params![user_id, website],
            |row| row.get(0),
        )
        .optional()?;
    Ok(save_password.unwrap_or(1) != 0)
}

async fn process_websocket_message(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    text: &str,
    ui_sender: &Sender<UiUpdate>,
    user_id: i32,
) -> WebSocketResponse {
    println!("WebSocket recebeu: {}", text);
    match text {
        t if t.starts_with("PREF:") => {
            let parts: Vec<&str> = t[5..].split("|").collect();
            if parts.len() == 3 {
                save_field_preference(conn, parts[0], parts[1], parts[2])
                    .map(|_| WebSocketResponse {
                        password: None,
                        username_email: None,
                        preferences: Vec::new(),
                        save_allowed: Some(get_website_preference(conn, user_id, parts[0]).unwrap_or(true)),
                        error: None,
                        multiple_accounts: None,
                    })
                    .unwrap_or_else(|e| WebSocketResponse {
                        password: None,
                        username_email: None,
                        preferences: Vec::new(),
                        save_allowed: None,
                        error: Some(e.to_string()),
                        multiple_accounts: None,
                    })
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
                retrieve_field_data(conn, user_id, hostname, role)
                    .map(|(value, selector)| {
                        let mut response = WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: vec![FieldPreference {
                                selector,
                                role: role.to_string(),
                            }],
                            save_allowed: Some(get_website_preference(conn, user_id, hostname).unwrap_or(true)),
                            error: None,
                            multiple_accounts: None,
                        };
                        if role == "password" {
                            response.password = value;
                        } else if role == "username" {
                            response.username_email = value;
                        }
                        response
                    })
                    .unwrap_or_else(|e| WebSocketResponse {
                        password: None,
                        username_email: None,
                        preferences: Vec::new(),
                        save_allowed: None,
                        error: Some(e.to_string()),
                        multiple_accounts: None,
                    })
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
                save_website_preference(conn, user_id, website, save_password)
                    .map(|_| WebSocketResponse {
                        password: None,
                        username_email: None,
                        preferences: Vec::new(),
                        save_allowed: Some(save_password),
                        error: None,
                        multiple_accounts: None,
                    })
                    .unwrap_or_else(|e| WebSocketResponse {
                        password: None,
                        username_email: None,
                        preferences: Vec::new(),
                        save_allowed: None,
                        error: Some(e.to_string()),
                        multiple_accounts: None,
                    })
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
                if !get_website_preference(conn, user_id, website).unwrap_or(true) {
                    let _ = ui_sender.send(UiUpdate::Error("Guardar passwords desligado para este website".to_string())).await;
                    return WebSocketResponse {
                        password: None,
                        username_email: None,
                        preferences: Vec::new(),
                        save_allowed: Some(false),
                        error: Some("Guardar passwords desligado para este website".to_string()),
                        multiple_accounts: None,
                    };
                }
                match add_password_with_selectors(conn, user_id, website, parts[1], parts[2], parts[3], parts[4]) {
                    Ok(()) => {
                        println!("Password recebida com sucesso, a atualizar ui");
                        let conn_clone = Arc::clone(conn);
                        let ui_sender_clone = ui_sender.clone();
                        tokio::spawn(async move {
                            let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                            let passwords = read_stored_passwords(&conn_clone, user_id, key)
                                .await
                                .unwrap_or_default();
                            let _ = ui_sender_clone
                                .send(UiUpdate::AddPasswordSuccess(passwords))
                                .await
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
                                },
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
            match retrieve_password_and_prefs(conn, user_id, website) {
                Ok(credentials) => {
                    println!("Informação passada: {:?}", credentials);
                    if credentials.is_empty() {
                        return WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: Vec::new(),
                            save_allowed: Some(get_website_preference(conn, user_id, website).unwrap_or(true)),
                            error: None,
                            multiple_accounts: None,
                        };
                    }
                    let prefs = credentials[0].2.clone(); // Now works with Clone
                    if credentials.len() == 1 {
                        let (password_opt, username_opt, _) = &credentials[0];
                        WebSocketResponse {
                            password: password_opt.clone(),
                            username_email: username_opt.clone(),
                            preferences: prefs,
                            save_allowed: Some(get_website_preference(conn, user_id, website).unwrap_or(true)),
                            error: None,
                            multiple_accounts: None,
                        }
                    } else {
                        WebSocketResponse {
                            password: None,
                            username_email: None,
                            preferences: prefs,
                            save_allowed: Some(get_website_preference(conn, user_id, website).unwrap_or(true)),
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

fn retrieve_field_data(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    user_id: i32,
    website: &str,
    role: &str,
) -> Result<(Option<String>, String)> {
    let db_conn = conn.get()?;
    let selector: String = db_conn
        .query_row(
            "SELECT selector FROM FieldPreferences WHERE website = ?1 AND role = ?2",
            params![website, role],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("No selector found for role {} on website {}", role, website))?;
    let value: Option<String> = if role == "password" {
        retrieve_password(conn, user_id, website)?
    } else {
        db_conn.query_row(
            "SELECT username_email FROM Passwords WHERE user_id = ?1 AND website = ?2",
            params![user_id, website],
            |row| row.get(0),
        )
        .optional()?
    };
    Ok((value, selector))
}

fn retrieve_password_and_prefs(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    user_id: i32,
    website: &str,
) -> Result<Vec<(Option<String>, Option<String>, Vec<FieldPreference>)>> {
    let key = ENCRYPTION_KEY
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| rusqlite::Error::QueryReturnedNoRows)?; // Simplified error for demo
    let pooled_conn = conn.get()?;
    
    let mut stmt = pooled_conn.prepare(
        "SELECT username_email, password FROM Passwords WHERE user_id = ?1 AND website = ?2",
    )?;
    let password_iter = stmt.query_map(params![user_id, website], |row| {
        let username_email: String = row.get(0)?;
        let encrypted_password: Vec<u8> = row.get(1)?;
        let decrypted_password = decrypt(&encrypted_password, &key)
            .map_err(|_e| rusqlite::Error::QueryReturnedNoRows)?; // Simplified error mapping
        let decrypted_password_str = String::from_utf8(decrypted_password)
            .map_err(|_e| rusqlite::Error::QueryReturnedNoRows)?; // Simplified error mapping
        Ok((Some(decrypted_password_str), Some(username_email)))
    })?;

    let mut credentials = Vec::new();
    for cred_result in password_iter {
        let (password_opt, username_opt) = cred_result?;
        let prefs = get_field_preferences(conn, website)?;
        credentials.push((password_opt, username_opt, prefs));
    }

    Ok(credentials)
}

fn save_field_preference(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    website: &str,
    selector: &str,
    role: &str,
) -> Result<()> {
    if role != "Username" && role != "Password" {
        return Err(anyhow!("Invalid role: {}", role));
    }
    let conn = conn.get()?;
    conn.execute(
        "INSERT OR REPLACE INTO FieldPreferences (website, selector, role) VALUES (?1, ?2, ?3)",
        params![website, selector, role],
    )?;
    println!(
        "Saved preference: website={}, selector={}, role={}",
        website, selector, role
    );
    Ok(())
}

fn get_field_preferences(conn: &Arc<Pool<SqliteConnectionManager>>, website: &str) -> Result<Vec<FieldPreference>> {
    let conn = conn.get()?;
    let mut stmt = conn.prepare("SELECT selector, role FROM FieldPreferences WHERE website = ?1")?;
    let pref_iter = stmt.query_map(params![website], |row| {
        Ok(FieldPreference {
            selector: row.get(0)?,
            role: row.get(1)?,
        })
    })?;
    pref_iter.collect::<Result<_, rusqlite::Error>>().map_err(|e| anyhow!(e))
}

fn retrieve_password(conn: &Arc<Pool<SqliteConnectionManager>>, user_id: i32, website: &str) -> Result<Option<String>> {
    let conn = conn.get()?;
    let mut stmt = conn.prepare("SELECT password FROM Passwords WHERE user_id = ?1 AND website = ?2")?;
    let encrypted_password: Option<Vec<u8>> = stmt.query_row(params![user_id, website], |row| row.get(0)).optional()?;
    let key = ENCRYPTION_KEY.lock().unwrap().clone().ok_or_else(|| anyhow!("Encryption key not set"))?;
    Ok(encrypted_password.map(|ep| decrypt_password(&ep, &key).unwrap_or("Decryption failed".to_string())))
}

fn add_password_with_selectors(
    conn: &Arc<Pool<SqliteConnectionManager>>,
    user_id: i32,
    website: &str,
    username_email: &str,
    password: &str,
    username_selector: &str,
    password_selector: &str,
) -> Result<()> {
    let key = ENCRYPTION_KEY
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Chave de encriptção não definida={}", user_id))?;
    println!("Chave de encriptação para: {}", user_id);

    let encrypted_password = encrypt(password.as_bytes(), &key)
        .map_err(|e| anyhow!("Falha ao encriptar password para website={}: {}", website, e))?;
    println!("Password encriptada com sucesso para website={}", website);

    let mut pooled_conn = conn
        .get()
        .map_err(|e| anyhow!("Falha ao conectar com a database para website={}: {}", website, e))?;
    println!("Database connection acquired for website={}", website);

    {
        let tx = pooled_conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| anyhow!("Falha na transação para website={}: {}", website, e))?;
        println!("Started transaction for adding/updating password for website={}", website);

        // Check if an entry exists for user_id, website, and username_email
        let existing_id: Option<i32> = tx
            .query_row(
                "SELECT id FROM Passwords WHERE user_id = ?1 AND website = ?2 AND username_email = ?3",
                params![user_id, website, username_email],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| anyhow!("Failed to check existing entry for website={}: {}", website, e))?;

        if let Some(id) = existing_id {
            // Update the existing password
            match tx.execute(
                "UPDATE Passwords SET password = ?1 WHERE id = ?2",
                params![&encrypted_password, id],
            ) {
                Ok(rows) => println!(
                    "Updated password for website={}, username={}, rows affected={}",
                    website, username_email, rows
                ),
                Err(e) => {
                    println!("Failed to update password: {}", e);
                    tx.rollback()
                        .map_err(|re| anyhow!("Rollback failed after update error: {}", re))?;
                    return Err(anyhow!(
                        "Failed to update password for website={}, username={}: {}",
                        website, username_email, e
                    ));
                }
            }
        } else {
            // Insert a new password entry
            match tx.execute(
                "INSERT INTO Passwords (user_id, website, username_email, password) VALUES (?1, ?2, ?3, ?4)",
                params![user_id, website, username_email, &encrypted_password],
            ) {
                Ok(rows) => println!(
                    "Inserted password for website={}, username={}, rows affected={}",
                    website, username_email, rows
                ),
                Err(e) => {
                    println!("Failed to insert password: {}", e);
                    tx.rollback()
                        .map_err(|re| anyhow!("Rollback failed after insert error: {}", re))?;
                    return Err(anyhow!(
                        "Failed to insert password for website={}, username={}: {}",
                        website, username_email, e
                    ));
                }
            }
        }

        // Update field preferences
        for (selector, role) in [(username_selector, "Username"), (password_selector, "Password")] {
            match tx.execute(
                "INSERT OR REPLACE INTO FieldPreferences (website, selector, role) VALUES (?1, ?2, ?3)",
                params![website, selector, role],
            ) {
                Ok(_) => println!(
                    "Saved preference: website={}, selector={}, role={}",
                    website, selector, role
                ),
                Err(e) => {
                    println!("Failed to save preference for website={}, role={}: {}", website, role, e);
                    tx.rollback()
                        .map_err(|re| anyhow!("Rollback failed after preference error: {}", re))?;
                    return Err(anyhow!(
                        "Failed to save preference for website={}, role={}: {}",
                        website, role, e
                    ));
                }
            }
        }

        tx.commit()
            .map_err(|e| anyhow!("Failed to commit transaction for website={}: {}", website, e))?;
        println!("Committed password and preferences for website={}", website);
    }

    // Verify the specific entry exists
    let count: i32 = pooled_conn
        .query_row(
            "SELECT COUNT(*) FROM Passwords WHERE user_id = ?1 AND website = ?2 AND username_email = ?3",
            params![user_id, website, username_email],
            |row| row.get(0),
        )
        .map_err(|e| anyhow!("Failed to verify entry for website={}: {}", website, e))?;
    println!("Password count for website={}, username={}: {}", website, username_email, count);
    if count == 0 {
        return Err(anyhow!(
            "Password entry not found after operation for website={}, username={}",
            website, username_email
        ));
    }

    let prefs = get_field_preferences(conn, website)?;
    println!("Saved preferences for website={}: {:?}", website, prefs);
    println!("Password and preferences successfully managed for website={}", website);
    Ok(())
}

fn spawn_ui_update_handler(weak_window: Weak<BlackSquareWindow>, mut ui_receiver: Receiver<UiUpdate>) {
    tokio::spawn(async move {
        while let Some(update) = ui_receiver.recv().await {
            slint::invoke_from_event_loop({
                let weak_window = weak_window.clone();
                move || {
                    if let Some(window) = weak_window.upgrade() {
                        match update {
                            UiUpdate::AddPasswordSuccess(passwords) => {
                                window.set_message("✅ Password adicionada com sucesso!".into());
                                window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                            }
                            UiUpdate::Error(msg) => window.set_message(format!("❌ {}", msg).into()),
                        }
                    }
                }
            }).expect("Failed to invoke from event loop");
        }
    });
}

fn setup_password_handlers(
    black_square_window: &BlackSquareWindow,
    conn: &Arc<Pool<SqliteConnectionManager>>,
    user_id: i32,
    db_path: PathBuf,
    masterkey_path: PathBuf,
) {
    let black_weak = black_square_window.as_weak();
    let conn = Arc::clone(conn);

    black_square_window.on_save_password({
        let black_weak = black_weak.clone();
        let conn = Arc::clone(&conn);
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

            slint::spawn_local({
                let black_weak = black_weak.clone();
                let conn = Arc::clone(&conn);
                async move {
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
                                    window.set_message(if window.get_isAddMode() { "Password adicionada com sucesso!" } else { "Password atualizada com sucesso!" }.into());
                                    window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                                }
                                Err(e) => window.set_message(format!("Error: {}", e).into()),
                            }
                        }
                    }).unwrap();
                }
            }).unwrap();
        }
    });

    black_square_window.on_websocket({
        let black_weak = black_weak.clone();
        let conn = Arc::clone(&conn);
        move |enabled| {
            let window = black_weak.upgrade().unwrap();
            if enabled {
                let (ui_sender, ui_receiver) = channel::<UiUpdate>(100);
                let handle = tokio::spawn(start_websocket_server(Arc::clone(&conn), ui_sender, user_id));
                *WEBSOCKET_TASK.lock().unwrap() = Some(handle);
                spawn_ui_update_handler(window.as_weak(), ui_receiver);
                window.set_message("✅ Websocket Iniciado!".into());
                window.set_websocket_enabled(true);
            } else {
                if let Some(shutdown_tx) = WEBSOCKET_SHUTDOWN.lock().unwrap().as_ref() {
                    let _ = shutdown_tx.send(true);
                    if let Some(handle) = WEBSOCKET_TASK.lock().unwrap().take() {
                        handle.abort();
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
        let conn = Arc::clone(&conn);
        move |id, website, username_email, password| {
            let window = black_weak.upgrade().unwrap();
            let (website, username_email, password) = (website.to_string(), username_email.to_string(), password.to_string());
            if website.is_empty() || username_email.is_empty() || password.is_empty() {
                window.set_message("Todos os campos precisam de ser preenchidos.".into());
                return;
            }

            slint::spawn_local({
                let black_weak = black_weak.clone();
                let conn = Arc::clone(&conn);
                async move {
                    let result = update_password(&conn, id, user_id, &website, &username_email, &password).await;
                    let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                    let passwords = read_stored_passwords(&conn, user_id, key).await.unwrap_or_default();
                    slint::invoke_from_event_loop(move || {
                        if let Some(window) = black_weak.upgrade() {
                            match result {
                                Ok(_) => {
                                    window.set_message("✅ Password atualizada com sucesso!".into());
                                    window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                                }
                                Err(e) => window.set_message(format!("❌ Erro ao atualizar a password: {}", e).into()),
                            }
                        }
                    }).unwrap();
                }
            }).unwrap();
        }
    });

    black_square_window.on_deletePassword({
        let black_weak = black_weak.clone();
        let conn = Arc::clone(&conn);
        move |id| {
            slint::spawn_local({
                let black_weak = black_weak.clone();
                let conn = Arc::clone(&conn);
                async move {
                    let result = delete_password(&conn, id, user_id).await;
                    let key = ENCRYPTION_KEY.lock().unwrap().clone().unwrap();
                    let passwords = read_stored_passwords(&conn, user_id, key).await.unwrap_or_default();
                    slint::invoke_from_event_loop(move || {
                        if let Some(window) = black_weak.upgrade() {
                            match result {
                                Ok(_) => {
                                    window.set_message("✅ Password deleteda !".into());
                                    window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                                }
                                Err(e) => window.set_message(format!("❌ Erro ao deletar password: {}", e).into()),
                            }
                        }
                    }).unwrap();
                }
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
                    window.set_message(format!("❌ Falha ao ativar autostart: {}", e).into());
                } else {
                    window.set_message("✅ Autostart ativado".into());
                }
            } else {
                if let Err(e) = remove_from_startup(app_name) {
                    window.set_message(format!("❌ Falha ao desativar autostart: {}", e).into());
                } else {
                    window.set_message("✅ Autostart desativado".into());
                }
            }
        }
    });
}

fn hash_password(password: &str, salt: &SaltString) -> Result<String> {
    Ok(Argon2::default().hash_password(password.as_bytes(), salt).map_err(|e| anyhow!(e))?.to_string())
}

async fn export_hash_to_file(hash: &str, file_path: &Path) -> Result<()> {
    let mut file = File::create(file_path).await?;
    file.write_all(hash.as_bytes()).await?;
    Ok(())
}

fn add_password(conn: &Arc<Pool<SqliteConnectionManager>>, user_id: i32, website: &str, username_email: &str, password: &str) -> Result<()> {
    let key = ENCRYPTION_KEY.lock().unwrap().clone().ok_or_else(|| anyhow!("Encryption key not set"))?;
    let encrypted_password = encrypt_password(password, &key)?;
    let conn = conn.get()?;
    conn.execute(
        "INSERT INTO Passwords (user_id, website, username_email, password) VALUES (?1, ?2, ?3, ?4)",
        params![user_id, website, username_email, &encrypted_password],
    )?;
    Ok(())
}

async fn update_password(conn: &Arc<Pool<SqliteConnectionManager>>, id: i32, user_id: i32, website: &str, username_email: &str, password: &str) -> Result<()> {
    let key = ENCRYPTION_KEY.lock().unwrap().clone().ok_or_else(|| anyhow!("Encryption key not set"))?;
    let encrypted_password = encrypt_password(password, &key)?;
    let conn = conn.get()?;
    let rows_affected = conn.execute(
        "UPDATE Passwords SET website = ?1, username_email = ?2, password = ?3 WHERE id = ?4 AND user_id = ?5",
        params![website, username_email, &encrypted_password, id, user_id],
    )?;
    if rows_affected == 0 {
        return Err(anyhow!("No matching record found to update"));
    }
    Ok(())
}

async fn delete_password(conn: &Arc<Pool<SqliteConnectionManager>>, id: i32, user_id: i32) -> Result<()> {
    let conn = conn.get()?;
    let rows_affected = conn.execute("DELETE FROM Passwords WHERE id = ?1 AND user_id = ?2", params![id, user_id])?;
    if rows_affected == 0 {
        return Err(anyhow!("No matching record found to delete"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn add_to_startup(app_name: &str, app_path: &str) -> Result<()> {
    use winreg::RegKey;
    use winreg::enums::*;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey_with_flags("Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_SET_VALUE)?;
    run_key.set_value(app_name, &app_path)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn remove_from_startup(app_name: &str) -> Result<()> {
    use winreg::RegKey;
    use winreg::enums::*;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey_with_flags("Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_SET_VALUE)?;
    run_key.delete_value(app_name)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_in_startup(app_name: &str) -> Result<bool> {
    use winreg::RegKey;
    use winreg::enums::*;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")?;
    Ok(run_key.get_value::<String, _>(app_name).is_ok())
}

#[cfg(target_os = "linux")]
fn add_to_startup(app_name: &str, app_path: &str) -> Result<()> {
    let desktop_content = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={}\n\
         Exec={}\n\
         Hidden=false\n\
         NoDisplay=false\n\
         X-GNOME-Autostart-enabled=true",
        app_name, app_path
    );
    let autostart_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("autostart");
    fs::create_dir_all(&autostart_dir)?;
    fs::write(autostart_dir.join(format!("{}.desktop", app_name)), desktop_content)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_from_startup(app_name: &str) -> Result<()> {
    let autostart_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("autostart");
    let path = autostart_dir.join(format!("{}.desktop", app_name));
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_in_startup(app_name: &str) -> Result<bool> {
    let autostart_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("autostart");
    Ok(autostart_dir.join(format!("{}.desktop", app_name)).exists())
}

#[cfg(target_os = "macos")]
fn add_to_startup(app_name: &str, app_path: &str) -> Result<()> {
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
        app_name, app_path
    );
    let launch_agents_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("Library/LaunchAgents");
    fs::create_dir_all(&launch_agents_dir)?;
    fs::write(launch_agents_dir.join(format!("com.{}.plist", app_name)), plist_content)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_from_startup(app_name: &str) -> Result<()> {
    let launch_agents_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("Library/LaunchAgents");
    let path = launch_agents_dir.join(format!("com.{}.plist", app_name));
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn is_in_startup(app_name: &str) -> Result<bool> {
    let launch_agents_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("Library/LaunchAgents");
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

fn derive_key(password: &str, salt: &str) -> Result<Vec<u8>> {
    let salt = SaltString::from_b64(salt).map_err(|e| anyhow!("Invalid salt: {}", e))?;
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt).map_err(|e| anyhow!(e))?;
    Ok(password_hash.hash.ok_or_else(|| anyhow!("No hash output"))?.as_bytes().to_vec())
}

fn encrypt_password(plaintext: &str, key: &[u8]) -> Result<Vec<u8>> {
    encrypt(plaintext.as_bytes(), key).map_err(|e| anyhow!("Encryption failed: {}", e))
}

fn decrypt_password(encrypted_data: &[u8], key: &[u8]) -> Result<String> {
    let plaintext = decrypt(encrypted_data, key)?;
    String::from_utf8(plaintext).map_err(|e| anyhow!("Invalid UTF-8 in decrypted data: {}", e))
}

#[tokio::main]
async fn main() -> Result<()> {
    
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
    setup_register_handler(ui.clone()).await;
    setup_import_handler(ui.clone(), black_square_window.clone()).await;

    let app_name = "EZPass";
    let app_path = std::env::current_exe()?.to_str().ok_or_else(|| anyhow!("Failed to get executable path"))?.to_string();
    if let Ok(is_enabled) = is_in_startup(app_name) {
        black_square_window.set_autostart_enabled(is_enabled);
    } else if add_to_startup(app_name, &app_path).is_ok() {
        black_square_window.set_autostart_enabled(true);
    }

    ui.show()?;
    slint::run_event_loop()?;
    Ok(())
}
