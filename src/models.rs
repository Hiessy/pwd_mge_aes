// models.rs
use serde::{Serialize, Deserialize};
use serde::ser::{SerializeStruct, Serializer};
use zeroize::Zeroizing;
use uuid::Uuid;

#[derive(Debug)]
pub struct PasswordEntry {
    pub id: Uuid,
    pub website: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub notes: Zeroizing<String>,
    pub tags: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PasswordVault {
    pub version: u8,
    pub entries: Vec<PasswordEntry>,
}

impl Serialize for PasswordEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PasswordEntry", 5)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("website", &self.website)?;
        state.serialize_field("username", &self.username)?;
        // Skip password field entirely
        state.serialize_field("notes", &*self.notes)?; // Deref to String
        state.serialize_field("tags", &self.tags)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PasswordEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Temp {
            id: Uuid,
            website: String,
            username: String,
            notes: String,
            tags: Vec<String>,
        }
        
        let temp = Temp::deserialize(deserializer)?;
        Ok(Self {
            id: temp.id,
            website: temp.website,
            username: temp.username,
            password: Zeroizing::new(String::new()), // Initialize empty
            notes: Zeroizing::new(temp.notes),
            tags: temp.tags,
        })
    }
}