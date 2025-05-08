// lib.rs
pub mod crypto;
pub mod models;
pub mod vault;
pub mod auth;
pub mod errors;

// Re-exports
pub use crypto::{AesKey, generate_iv};
pub use models::{PasswordEntry, PasswordVault};
pub use vault::VaultManager;
pub use auth::derive_key;

#[cfg(feature = "python")]
pub mod python;

// In lib.rs
#[cfg(test)]
mod tests {
    mod crypto_test;
    mod vault_test;
    mod auth_test;
    mod models_test;
}