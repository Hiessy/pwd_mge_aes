// tests/auth_test.rs
use crate::auth;

#[test]
fn test_key_derivation_time() {
    use std::time::Instant;
    
    let start = Instant::now();
    let _key = auth::derive_key("secure password");
    let duration = start.elapsed();
    
    // Ensure Argon2 isn't too fast (minimum 100ms)
    assert!(duration > std::time::Duration::from_millis(100));
}

#[test]
fn test_key_uniqueness() {
    let key1 = auth::derive_key("password");
    let key2 = auth::derive_key("password");
    
    // Different salts should produce different keys
    assert_ne!(key1.as_bytes(), key2.as_bytes());
}