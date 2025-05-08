// tests/vault_test.rs
use crate::{VaultManager, PasswordVault, derive_key};
use tempfile::NamedTempFile;

#[test]
fn test_vault_roundtrip() {
    let key = derive_key("master password");
    let temp_file = NamedTempFile::new().unwrap();
    
    let manager = VaultManager::new(key, temp_file.path());
    let vault = PasswordVault {
        version: 1,
        entries: vec![],
    };
    
    manager.save(&vault).unwrap();
    let loaded = manager.load().unwrap();
    
    assert_eq!(vault.version, loaded.version);
}

#[test]
#[should_panic(expected = "Invalid ciphertext length")]
fn test_corrupted_vault() {
    let key = derive_key("test");
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), "garbage data").unwrap();
    
    let manager = VaultManager::new(key, temp_file.path());
    let _ = manager.load().unwrap(); // Should fail with our expected error
}