use crate::crypt::{AesKey, encrypt_cbc, decrypt_cbc};

pub struct VaultManager {
    key: AesKey,
    iv: [u8; 16],
    path: PathBuf,
}

impl VaultManager {
    pub fn new(key: AesKey, path: impl AsRef<Path>) -> Self {
        Self {
            key,
            iv: generate_iv(),
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn save(&self, vault: &PasswordVault) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = Zeroizing::new(serde_json::to_vec(vault)?);
        let encrypted = encrypt_cbc(&self.key, &self.iv, &String::from_utf8(serialized.to_vec())?);
        std::fs::write(&self.path, &*encrypted)?;
        Ok(())
    }

    pub fn load(&self) -> Result<PasswordVault, Box<dyn std::error::Error>> {
        let encrypted = std::fs::read(&self.path)?;
        let decrypted = decrypt_cbc(&self.key, &self.iv, &encrypted)?;
        Ok(serde_json::from_str(&decrypted)?)
    }
}