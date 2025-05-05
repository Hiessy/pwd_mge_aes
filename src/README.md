# Rust Password Manager Core

Secure AES-256 encryption for password management.

## Features
- AES-256-CBC encryption
- Automatic memory zeroing
- Type-safe API

## Usage
```rust
use pwd_mgr_rs::{AesKey, generate_iv, encrypt_cbc, decrypt_cbc};

let key = AesKey::random();
let iv = generate_iv();

let ciphertext = encrypt_cbc(&key, &iv, "password123");
let decrypted = decrypt_cbc(&key, &iv, &ciphertext).unwrap();
```

## Testing
```bash
cargo test
```
