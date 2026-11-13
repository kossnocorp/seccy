//! XDG paths and persistent public-key files. Private keys never live here.
use crate::{Config, Identity, KeyStore, Mode};
use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

pub struct Paths {
    pub config: PathBuf,
    pub keys: PathBuf,
    pub runtime: PathBuf,
    pub state: PathBuf,
}

impl Paths {
    pub fn from_env() -> Result<Self> {
        let home = env::var_os("HOME").map(PathBuf::from);
        Self::resolve(home.as_deref(), |name| env::var_os(name).map(PathBuf::from))
    }

    pub fn resolve(home: Option<&Path>, get: impl Fn(&str) -> Option<PathBuf>) -> Result<Self> {
        let base = |name, fallback| -> Result<PathBuf> {
            match get(name).filter(|p| p.is_absolute()) {
                Some(path) => Ok(path),
                None => Ok(home
                    .filter(|p| p.is_absolute())
                    .context("HOME must be absolute when XDG directories are unset")?
                    .join(fallback)),
            }
        };
        let runtime = match get("XDG_RUNTIME_DIR").filter(|p| p.is_absolute()) {
            Some(path) => path.join("seccy"),
            None => base("XDG_STATE_HOME", ".local/state")?.join("seccy"),
        };
        Ok(Self {
            config: base("XDG_CONFIG_HOME", ".config")?.join("seccy/config.toml"),
            keys: base("XDG_STATE_HOME", ".local/state")?.join("seccy/keys"),
            state: base("XDG_STATE_HOME", ".local/state")?.join("seccy"),
            runtime,
        })
    }

    pub fn public_key(&self, name: &str) -> PathBuf {
        self.keys.join(format!("{name}.pub"))
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Provisioned,
    NotProvisioned,
}

#[derive(Debug, Serialize)]
pub struct KeyInfo {
    pub provider: Option<crate::config::Resolved>,
    #[serde(rename = "use")]
    pub uses: Option<crate::config::Many<crate::config::Use>>,
    pub display_name: Option<String>,
    pub secrets: bool,
    pub config: Option<String>,
    pub name: String,
    pub mode: Mode,
    pub status: KeyStatus,
    pub public_key_path: PathBuf,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
    pub synced: bool,
}

impl KeyInfo {
    pub fn new(name: &str, mode: Mode, identity: Option<&Identity>, paths: &Paths) -> Result<Self> {
        let path = paths.public_key(name);
        let synced = match identity {
            Some(key) => contents_match(&path, &format!("{}\n", key.public_key))?,
            None => false,
        };
        Ok(Self {
            provider: None,
            uses: identity.and_then(|i| i.uses.clone()),
            display_name: identity.and_then(|i| i.display_name.clone()),
            config: None,
            secrets: false,
            name: name.into(),
            mode,
            status: if identity.is_some() {
                KeyStatus::Provisioned
            } else {
                KeyStatus::NotProvisioned
            },
            public_key_path: path,
            public_key: identity.map(|k| k.public_key.clone()),
            fingerprint: identity.map(|k| k.fingerprint.clone()),
            synced,
        })
    }

    pub fn text(&self) -> String {
        let status = match self.status {
            KeyStatus::Provisioned => "provisioned",
            KeyStatus::NotProvisioned => "not_provisioned",
        };
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.name,
            self.mode.as_str(),
            status,
            if self.synced { "synced" } else { "not_synced" },
            self.public_key_path.display(),
            self.config.as_deref().unwrap_or("-")
        )
    }
}

pub fn key_info(
    store: &impl KeyStore,
    config: &Config,
    paths: &Paths,
    name: &str,
) -> Result<Option<KeyInfo>> {
    let Some(_key) = config.keys.get(name) else {
        return Ok(None);
    };
    let policy = config.resolve(name)?;
    policy.ensure_available()?;
    let identity = store
        .identity(name, policy.mode)?
        .map(|i| i.with_email(config.effective_email(name)));
    Ok(Some(KeyInfo::new(
        name,
        policy.mode,
        identity.as_ref(),
        paths,
    )?))
}

fn contents_match(path: &Path, expected: &str) -> Result<bool> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes == expected.as_bytes()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Atomically replace missing/outdated public files; leave identical files alone.
pub fn sync_public_key(identity: &Identity, paths: &Paths) -> Result<bool> {
    let path = paths.public_key(&identity.name);
    let content = format!("{}\n", identity.public_key);
    if contents_match(&path, &content)? {
        return Ok(false);
    }
    fs::create_dir_all(&paths.keys)?;
    let mut temporary = tempfile::NamedTempFile::new_in(&paths.keys)?;
    temporary.write_all(content.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(&path)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}
