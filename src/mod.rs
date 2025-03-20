// src/mod.rs

// Declare the modules
pub mod ui;
pub mod backend;

// Re-export commonly used items for easier access
pub use ui::{LoginWindow, BlackSquareWindow, setup_ui_handlers};
pub use backend::{SqlitePool, start_websocket_server, hash_all_databases};