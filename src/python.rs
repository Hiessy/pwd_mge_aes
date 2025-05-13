// python.rs
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use pyo3::types::PyDict;
use crate::{auth::derive_key, crypto::AesKey, models::PasswordEntry, vault::VaultManager};
use std::path::PathBuf;
use uuid::Uuid;

/// Python module for the password vault
#[pymodule]
fn password_vault(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyPasswordEntry>()?;
    m.add_class::<PyVaultManager>()?;
    m.add_function(wrap_pyfunction!(create_key, m)?)?;
    Ok(())
}

/// Python wrapper for PasswordEntry
#[pyclass]
struct PyPasswordEntry {
    inner: PasswordEntry,
}

#[pymethods]
impl PyPasswordEntry {
    #[new]
    fn new(website: String, username: String, password: String, notes: String, tags: Vec<String>) -> Self {
        PyPasswordEntry {
            inner: PasswordEntry {
                id: Uuid::new_v4(),
                website,
                username,
                password: zeroize::Zeroizing::new(password),
                notes: zeroize::Zeroizing::new(notes),
                tags,
            },
        }
    }

    #[getter]
    fn id(&self) -> String {
        self.inner.id.to_string()
    }

    #[getter]
    fn website(&self) -> &str {
        &self.inner.website
    }

    #[getter]
    fn username(&self) -> &str {
        &self.inner.username
    }

    #[getter]
    fn password(&self) -> PyResult<String> {
        Ok(self.inner.password.to_string())
    }

    #[getter]
    fn notes(&self) -> PyResult<String> {
        Ok(self.inner.notes.to_string())
    }

    #[getter]
    fn tags(&self) -> Vec<String> {
        self.inner.tags.clone()
    }

    fn to_dict(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        dict.set_item("id", self.id())?;
        dict.set_item("website", self.website())?;
        dict.set_item("username", self.username())?;
        dict.set_item("password", self.password()?)?;
        dict.set_item("notes", self.notes()?)?;
        dict.set_item("tags", self.tags())?;
        Ok(dict.into())
    }
}

/// Python wrapper for VaultManager
#[pyclass]
struct PyVaultManager {
    inner: VaultManager,
}

#[pymethods]
impl PyVaultManager {
    #[new]
    fn new(key: Vec<u8>, path: String) -> PyResult<Self> {
        if key.len() != 32 {
            return Err(PyValueError::new_err("Key must be 32 bytes"));
        }
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key);
        
        Ok(PyVaultManager {
            inner: VaultManager::new(crate::crypto::AesKey::new(key_bytes), PathBuf::from(path)),
        })
    }

    fn save(&self, entries: Vec<PyRef<PyPasswordEntry>>) -> PyResult<()> {
        let vault = crate::models::PasswordVault {
            version: 1,
            entries: entries.iter().map(|e| e.inner.clone()).collect(),
        };
        self.inner.save(&vault)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn load(&self) -> PyResult<Vec<PyPasswordEntry>> {
        let vault = self.inner.load()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        
        Ok(vault.entries.into_iter()
            .map(|e| PyPasswordEntry { inner: e })
            .collect())
    }
}

/// Derive a key from a password
#[pyfunction]
fn create_key(password: &str) -> PyResult<Vec<u8>> {
    let key = derive_key(password);
    Ok(key.as_bytes().to_vec())
}