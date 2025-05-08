// errors.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("Serialization error")]
    Serde(#[from] serde_json::Error),
    #[error("Crypto error")]
    Crypto(String),
    // Add more error variants as needed
}