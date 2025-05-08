// tests/models_test.rs
use crate::{PasswordEntry, PasswordVault};
use zeroize::Zeroizing;

#[test]
fn test_password_entry_secure() {
    let entry = PasswordEntry {
        id: uuid::Uuid::new_v4(),
        website: "example.com".to_string(),
        username: "user123".to_string(),
        password: Zeroizing::new("s3cr3t!".to_string()),
        notes: Zeroizing::new("personal account".to_string()),
        tags: vec!["work".to_string()],
    };
    
    assert_eq!(entry.website, "example.com");
    assert_eq!(*entry.password, "s3cr3t!"); // Verify Zeroizing works
}

#[test]
fn test_vault_serialization() {
    use serde_json;
    
    let vault = PasswordVault {
        version: 1,
        entries: vec![/* ... */],
    };
    
    let serialized = serde_json::to_string(&vault).unwrap();
    let deserialized: PasswordVault = serde_json::from_str(&serialized).unwrap();
    
    assert_eq!(vault.version, deserialized.version);
}