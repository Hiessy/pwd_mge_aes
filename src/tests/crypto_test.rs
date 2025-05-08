// tests/crypto_test.rs
use crate::crypto::*;
use crate::auth::derive_key;

#[test]
fn test_key_zeroization() {
    let key = AesKey::random();
    let ptr = key.as_bytes().as_ptr() as usize;
    let key_copy = *key.as_bytes(); // Copy before drop
    
    // Drop the key (should trigger zeroization)
    std::mem::drop(key);
    
    // Verify the copy still exists (original should be zeroized)
    assert!(
        key_copy.iter().any(|&x| x != 0),
        "Key copy was zeroized unexpectedly"
    );
    
    // Safety: This is just for testing zeroization
    unsafe {
        let slice = std::slice::from_raw_parts(ptr as *const u8, 32);
        assert!(
            slice.iter().all(|&x| x == 0),
            "Memory not zeroized: {:?}",
            slice
        );
    }
}

#[test]
fn test_argon2_derivation() {
    let key1 = derive_key("password");
    let key2 = derive_key("password");
    let key3 = derive_key("different");
    
    assert_ne!(key1.as_bytes(), key3.as_bytes());
    // Shouldn't match even with same input (different salt)
    assert_ne!(key1.as_bytes(), key2.as_bytes()); 
}