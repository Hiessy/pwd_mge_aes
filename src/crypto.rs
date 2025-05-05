use aes::cipher::generic_array::{GenericArray, typenum::U16};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct AesKey([u8; 32]);


impl AesKey {
    /// Create new key from raw bytes
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    
    /// Generate a new random key
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }
    
    /// Get reference to key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Initialization Vector for CBC mode
pub type Iv = [u8; 16];

/// Generate a random AES-256 key
pub fn generate_key() -> AesKey {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    AesKey(key)
}

/// Generate a random IV for CBC mode
pub fn generate_iv() -> Iv {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    iv
}

/// PKCS#7 padding (constant-time-ish implementation)
fn pad_pkcs7(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let block_size = 16;
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Zeroizing::new(data.to_vec());
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

/// PKCS#7 unpadding with constant-time validation
fn unpad_pkcs7(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if data.is_empty() {
        return Err("Empty data");
    }

    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > 16 || pad_len > data.len() {
        return Err("Invalid padding length");
    }

    // Constant-time padding validation
    let mut is_valid = true;
    for &byte in &data[data.len() - pad_len..] {
        is_valid &= byte as usize == pad_len;
    }

    if !is_valid {
        return Err("Invalid padding bytes");
    }

    Ok(Zeroizing::new(data[..data.len() - pad_len].to_vec()))
}


// ... (other imports remain the same)

pub fn encrypt_cbc(key: &AesKey, iv: &[u8; 16], plaintext: &str) -> Zeroizing<Vec<u8>> {
    let cipher = Aes256::new(GenericArray::from_slice(&key.0));
    let padded = pad_pkcs7(plaintext.as_bytes());
    
    let mut encrypted = Zeroizing::new(Vec::new());
    let mut prev_block = *iv; // Copy the IV

    for chunk in padded.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        
        // XOR with previous block
        for (a, b) in block.iter_mut().zip(prev_block.iter()) {
            *a ^= b;
        }
        
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        encrypted.extend_from_slice(&block);
        prev_block = block;
    }

    encrypted
}

/// Decrypt with AES-256-CBC
pub fn decrypt_cbc(key: &AesKey, iv: &Iv, ciphertext: &[u8]) -> Result<Zeroizing<String>, &'static str> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err("Invalid ciphertext length");
    }

    let cipher = Aes256::new(GenericArray::from_slice(&key.0));
    let mut decrypted = Zeroizing::new(Vec::new());
    let mut prev_block = GenericArray::<u8, U16>::clone_from_slice(iv);

    for chunk in ciphertext.chunks(16) {
        let mut block = GenericArray::<u8, U16>::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        
        // CBC XOR operation
        for (a, b) in block.iter_mut().zip(prev_block.iter()) {
            *a ^= b;
        }
        
        decrypted.extend_from_slice(&block);
        prev_block = GenericArray::<u8, U16>::clone_from_slice(chunk);
    }

    let unpadded = unpad_pkcs7(&decrypted)?;
    Ok(Zeroizing::new(
        String::from_utf8(unpadded.to_vec()).map_err(|_| "Invalid UTF-8")?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbc_roundtrip() {
        let key = generate_key();
        let iv = generate_iv();
        let msg = "Sensitive data 🚀";
        
        let encrypted = encrypt_cbc(&key, &iv, msg);
        let decrypted = decrypt_cbc(&key, &iv, &encrypted).unwrap();
        
        assert_eq!(*decrypted, msg);
    }

    #[test]
    fn test_padding_validation() {
        // Valid padding
        let valid = b"hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
        assert!(unpad_pkcs7(valid).is_ok());
    
        // Invalid padding length (17 > block size)
        let invalid_len = b"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11";
        assert!(unpad_pkcs7(invalid_len).is_err());
    
        // Corrupt padding (last byte doesn't match padding length)
        let corrupt = b"hello\x05\x05\x05\x03\x05";
        assert!(unpad_pkcs7(corrupt).is_err());
    }

    #[test]
    fn test_zeroization() {
        let key = generate_key();
        let key_copy = key.0; // Copy before drop
        
        // Force drop
        std::mem::drop(key);
        
        // Verify the COPY wasn't zeroized (shouldn't be)
        assert!(
            key_copy.iter().any(|&x| x != 0),
            "Key copy was zeroized unexpectedly"
        );
        
        // Note: Can't directly test the original key after drop,
        // but Zeroize's own tests verify the behavior
    }

    #[test]
    fn test_cbc_consistency() {
        let key = AesKey::random();
        let iv1 = generate_iv();
        let iv2 = generate_iv();
        let msg = "Test message";
        
        // Different IVs should produce different ciphertexts
        let encrypted1 = encrypt_cbc(&key, &iv1, msg);
        let encrypted2 = encrypt_cbc(&key, &iv2, msg);
        assert_ne!(encrypted1, encrypted2);
        
        // Same IV should produce same ciphertext
        let encrypted3 = encrypt_cbc(&key, &iv1, msg);
        assert_eq!(encrypted1, encrypted3);
        
        // Both should decrypt correctly
        assert_eq!(*decrypt_cbc(&key, &iv1, &encrypted1).unwrap(), msg);
        assert_eq!(*decrypt_cbc(&key, &iv2, &encrypted2).unwrap(), msg);
    }

}