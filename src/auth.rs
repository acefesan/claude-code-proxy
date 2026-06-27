use anyhow::Result;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::to_string_pretty;
use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub trait AuthStorage<T>: Send + Sync
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone,
{
    fn load(&self) -> Result<Option<T>>;
    fn save(&self, value: T) -> Result<()>;
    fn clear(&self) -> Result<()>;
    fn path(&self) -> String;
}

pub trait Keychain: Send + Sync {
    fn read(&self, _service: &str, _account: &str) -> Option<String>;
    fn write(&self, _service: &str, _account: &str, _value: &str) -> bool;
    fn delete(&self, _service: &str, _account: &str) -> bool;
}

#[derive(Default)]
pub struct StubKeychain;

impl Keychain for StubKeychain {
    fn read(&self, _service: &str, _account: &str) -> Option<String> {
        None
    }

    fn write(&self, _service: &str, _account: &str, _value: &str) -> bool {
        true
    }

    fn delete(&self, _service: &str, _account: &str) -> bool {
        true
    }
}

pub struct FileAuthStore<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone,
{
    file: String,
    legacy_file: String,
    _marker: std::marker::PhantomData<T>,
}

impl<T> FileAuthStore<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone,
{
    pub fn new(file: String, legacy_file: String) -> Self {
        Self {
            file,
            legacy_file,
            _marker: Default::default(),
        }
    }
}

impl<T> AuthStorage<T> for FileAuthStore<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone,
{
    fn load(&self) -> Result<Option<T>> {
        let parsed = load_auth_file::<T>(&self.file);
        if parsed.is_some() {
            return Ok(parsed);
        }
        if self.file == self.legacy_file {
            return Ok(None);
        }
        Ok(load_auth_file::<T>(&self.legacy_file))
    }

    fn save(&self, value: T) -> Result<()> {
        let path = std::path::Path::new(&self.file);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
            set_mode(dir, 0o700);
        }
        write_atomically(&self.file, &value)
    }

    fn clear(&self) -> Result<()> {
        for path in [&self.file, &self.legacy_file] {
            if let Err(err) = fs::remove_file(path)
                && err.kind() != io::ErrorKind::NotFound
            {
                return Err(anyhow::Error::from(err));
            }
        }
        Ok(())
    }

    fn path(&self) -> String {
        self.file.clone()
    }
}

pub fn load_auth_file<T: DeserializeOwned>(path: &str) -> Option<T> {
    let mut file = File::open(path).ok()?;
    let mut raw = String::new();
    file.read_to_string(&mut raw).ok()?;
    serde_json::from_str::<T>(&raw).ok()
}

pub fn load_auth_file_value(path: &std::path::Path) -> Option<serde_json::Value> {
    let mut file = File::open(path).ok()?;
    let mut raw = String::new();
    file.read_to_string(&mut raw).ok()?;
    serde_json::from_str::<serde_json::Value>(&raw).ok()
}

pub fn load_auth_file_with_legacy<T: DeserializeOwned>(
    primary: &std::path::Path,
    legacy: &std::path::Path,
) -> Option<T> {
    if let Some(value) = load_auth_file_value(primary) {
        return serde_json::from_value(value).ok();
    }
    if primary == legacy {
        None
    } else {
        load_auth_file_value(legacy).and_then(|value| serde_json::from_value(value).ok())
    }
}

pub fn delete_auth_file(primary: &std::path::Path, legacy: &std::path::Path) -> io::Result<()> {
    if let Err(err) = fs::remove_file(primary)
        && err.kind() != io::ErrorKind::NotFound
    {
        return Err(err);
    }
    if primary != legacy
        && let Err(err) = fs::remove_file(legacy)
        && err.kind() != io::ErrorKind::NotFound
    {
        return Err(err);
    }
    Ok(())
}

pub fn write_atomically<T: Serialize>(path: &str, value: &T) -> Result<()> {
    let dir = std::path::Path::new(path)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid auth path"))?;
    fs::create_dir_all(dir)?;
    set_mode(dir, 0o700);

    let tmp = format!("{path}.tmp-{}", std::process::id());
    let mut out = File::create(&tmp)?;
    out.write_all(to_string_pretty(value)?.as_bytes())?;
    out.sync_all()?;
    fs::rename(&tmp, path)?;
    set_mode(std::path::Path::new(path), 0o600);
    Ok(())
}

fn set_mode(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        if let Ok(meta) = fs::metadata(path) {
            let mut permissions = meta.permissions();
            permissions.set_mode(mode);
            let _ = fs::set_permissions(path, permissions);
        }
    }
}

pub struct InMemoryAuthStore<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone,
{
    inner: std::sync::Arc<std::sync::Mutex<Option<T>>>,
}

impl<T> Default for InMemoryAuthStore<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> InMemoryAuthStore<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone,
{
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl<T> Clone for InMemoryAuthStore<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> AuthStorage<T> for InMemoryAuthStore<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone,
{
    fn load(&self) -> Result<Option<T>> {
        let inner = self
            .inner
            .lock()
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        Ok(inner.clone())
    }

    fn save(&self, value: T) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        *inner = Some(value);
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        *inner = None;
        Ok(())
    }

    fn path(&self) -> String {
        "memory".to_string()
    }
}

#[cfg(test)]
pub fn fixture_store<T>() -> InMemoryAuthStore<T>
where
    T: Serialize + serde::de::DeserializeOwned + Send + Sync + Clone,
{
    InMemoryAuthStore::new()
}
