use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct PasswordEntry {
    pub id: uuid::Uuid,
    pub website: String,
    pub username: String,
    #[serde(skip_serializing)]  // Never log/display
    pub password: Zeroizing<String>,
    pub notes: Zeroizing<String>,
    pub tags: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PasswordVault {
    pub version: u8,
    pub entries: Vec<PasswordEntry>,
}