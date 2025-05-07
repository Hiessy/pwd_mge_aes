use argon2::{Argon2, PasswordHasher, password_hash::{SaltString, rand_core::OsRng}};

pub fn derive_key(password: &str) -> AesKey {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
    AesKey::new(hash.hash.unwrap().as_bytes()[..32].try_into().unwrap())
}