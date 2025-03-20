// src/ui.rs

use std::sync::Arc;
use slint::{SharedString, ModelRc, VecModel, Weak};
use crate::backend::{SqlitePool, check_login, forgot_password, register_user, 
                    add_password, update_password, delete_password, read_stored_passwords, 
                    hash_all_databases};

slint::include_modules!();

pub fn setup_ui_handlers(
    ui: Arc<LoginWindow>,
    black_square_window: Arc<BlackSquareWindow>,
    login_pool: SqlitePool,
    pass_pool: SqlitePool,
    db_paths: Vec<&'static str>,
) {
    // Login handler
    let ui_handle = ui.as_weak();
    let login_pool_clone = Arc::clone(&login_pool);
    let pass_pool_clone = Arc::clone(&pass_pool);
    let black_square_handle = black_square_window.as_weak();
    ui.on_login_clicked(move || {
        let ui = ui_handle.upgrade().unwrap();
        let username = ui.get_username().to_string();
        let password = ui.get_password().to_string();

        if username.is_empty() || password.is_empty() {
            ui.set_message(SharedString::from("Please enter a username and password."));
            return;
        }

        let login_pool = Arc::clone(&login_pool_clone);
        let pass_pool = Arc::clone(&pass_pool_clone);
        let ui_handle = ui.as_weak();
        let black_square_handle = black_square_handle.clone();

        slint::spawn_local(async move {
            let result = check_login(
                &login_pool,
                &pass_pool,
                &username,
                &password,
                ui_handle.clone(),
                black_square_handle.clone(),
            ).await;

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    match result {
                        Ok(true) => {
                            ui.set_message(SharedString::from("Login successful!"));
                            ui.set_username(SharedString::from(""));
                            ui.set_password(SharedString::from(""));
                            ui.hide().unwrap();
                        }
                        Ok(false) => ui.set_message(SharedString::from("Invalid username or password.")),
                        Err(e) => ui.set_message(SharedString::from(format!("Login error: {}", e))),
                    }
                }
            }).unwrap();
        }).unwrap();
    });

    // Forgot password handler
    let ui_handle = ui.as_weak();
    let login_pool_clone = Arc::clone(&login_pool);
    let black_square_handle = black_square_window.as_weak();
    ui.on_forgot_password(move || {
        let ui = ui_handle.upgrade().unwrap();
        let username = ui.get_username().to_string();

        if username.is_empty() {
            ui.set_message(SharedString::from("Please enter your username before recovering your password."));
            return;
        }

        let login_pool = Arc::clone(&login_pool_clone);
        let ui_handle = ui.as_weak();
        let black_square_handle = black_square_handle.clone();

        slint::spawn_local(async move {
            let result = forgot_password(&login_pool, &username, black_square_handle.clone()).await;

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    match result {
                        Ok(_) => {
                            ui.set_message(SharedString::from("Password recovery process started."));
                            ui.hide().unwrap();
                        }
                        Err(e) => ui.set_message(SharedString::from(format!("Password recovery error: {}", e))),
                    }
                }
            }).unwrap();
        }).unwrap();
    });

    // Register handler
    let ui_handle = ui.as_weak();
    let login_pool_clone = Arc::clone(&login_pool);
    ui.on_register_clicked(move || {
        let ui = ui_handle.upgrade().unwrap();
        let username = ui.get_username().to_string();
        let password = ui.get_password().to_string();

        if username.is_empty() || password.is_empty() {
            ui.set_message(SharedString::from("Please enter both username and password."));
            return;
        }

        let login_pool = Arc::clone(&login_pool_clone);
        let ui_handle = ui.as_weak();
        let db_paths = db_paths.clone();

        slint::spawn_local(async move {
            let result = register_user(login_pool, username, password).await;

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
                            let msg = if e.to_string().contains("UNIQUE constraint failed") {
                                "Username already exists. Please choose another."
                            } else if e.to_string().contains("User cancelled file save") {
                                "Registration failed: You must save the master key file."
                            } else {
                                &format!("Registration failed: {}", e)
                            };
                            ui.set_message(SharedString::from(msg));
                        }
                    }
                }
            }).unwrap();
        }).unwrap();
    });

    // Save password handler
    let pass_pool_clone = Arc::clone(&pass_pool);
    let black_square_handle = black_square_window.as_weak();
    black_square_window.on_savePassword(move || {
        let window = black_square_handle.upgrade().unwrap();
        let website = window.get_selected_website().to_string();
        let username_email = window.get_selected_username_email().to_string();
        let password = window.get_selected_password().to_string();

        if website.is_empty() || username_email.is_empty() || password.is_empty() {
            window.set_message(SharedString::from("All fields are required."));
            return;
        }

        let pass_pool = Arc::clone(&pass_pool_clone);
        let window_handle = window.as_weak();

        slint::spawn_local(async move {
            let result = if window.get_isAddMode() {
                add_password(&pass_pool, &website, &username_email, &password).await
            } else {
                update_password(&pass_pool, window.get_id(), &website, &username_email, &password).await
            };
            let passwords = read_stored_passwords(&pass_pool).await.unwrap_or_default();

            slint::invoke_from_event_loop(move || {
                if let Some(window) = window_handle.upgrade() {
                    match result {
                        Ok(_) => {
                            let msg = if window.get_isAddMode() {
                                "Password added successfully!"
                            } else {
                                "Password updated successfully!"
                            };
                            window.set_message(SharedString::from(msg));
                            window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                        }
                        Err(e) => window.set_message(SharedString::from(format!("Error: {}", e))),
                    }
                }
            }).unwrap();
        }).unwrap();
    });

    // Edit password handler
    let pass_pool_clone = Arc::clone(&pass_pool);
    let black_square_handle = black_square_window.as_weak();
    black_square_window.on_edit(move |id, website, username_email, new_password| {
        let window = black_square_handle.upgrade().unwrap();
        let website = website.to_string();
        let username_email = username_email.to_string();
        let new_password = new_password.to_string();

        if website.is_empty() || username_email.is_empty() || new_password.is_empty() {
            window.set_message(SharedString::from("All fields must be filled."));
            return;
        }

        let pass_pool = Arc::clone(&pass_pool_clone);
        let window_handle = window.as_weak();

        slint::spawn_local(async move {
            let result = update_password(&pass_pool, id, &website, &username_email, &new_password).await;
            let passwords = read_stored_passwords(&pass_pool).await.unwrap_or_default();

            slint::invoke_from_event_loop(move || {
                if let Some(window) = window_handle.upgrade() {
                    match result {
                        Ok(_) => {
                            window.set_message(SharedString::from("✅ Password updated successfully!"));
                            window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                        }
                        Err(e) => window.set_message(SharedString::from(format!("❌ Error updating password: {}", e))),
                    }
                }
            }).unwrap();
        }).unwrap();
    });

    // Delete password handler
    let pass_pool_clone = Arc::clone(&pass_pool);
    let black_square_handle = black_square_window.as_weak();
    black_square_window.on_deletePassword(move |id| {
        let window = black_square_handle.upgrade().unwrap();
        let pass_pool = Arc::clone(&pass_pool_clone);
        let window_handle = window.as_weak();

        slint::spawn_local(async move {
            let result = delete_password(&pass_pool, id).await;
            let passwords = read_stored_passwords(&pass_pool).await.unwrap_or_default();

            slint::invoke_from_event_loop(move || {
                if let Some(window) = window_handle.upgrade() {
                    match result {
                        Ok(_) => {
                            window.set_message(SharedString::from("✅ Password deleted successfully!"));
                            window.set_password_entries(ModelRc::new(VecModel::from(passwords)));
                        }
                        Err(e) => window.set_message(SharedString::from(format!("❌ Error deleting password: {}", e))),
                    }
                }
            }).unwrap();
        }).unwrap();
    });
}