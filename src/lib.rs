// lib.rs
pub mod crypto;      // Your existing AES implementation
pub mod models;     // PasswordEntry/Vault structs
pub mod vault;      // VaultManager
pub mod auth;       // Key derivation
pub mod errors;     // Custom error handling

// Re-export main functionality
pub use vault::VaultManager;
pub use models::{PasswordEntry, PasswordVault};
pub use auth::derive_key;

#[cfg(feature = "python")]
pub mod python;     // PyO3 bindings (optional)