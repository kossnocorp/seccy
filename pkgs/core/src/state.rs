//! Persistent inventory. Source configurations are provisioning inputs only.
use crate::{
    Config, Identity, KeyConfig, KeyStore, Mode, UserConfig,
    storage::{KeyInfo, Paths},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub mode: Mode,
    pub config: PathBuf,
    pub email: Option<String>,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    #[serde(default)]
    pub keys: BTreeMap<String, Record>,
}

impl State {
    pub fn load(paths: &Paths) -> Result<Self> {
        let text = match fs::read_to_string(paths.state.join("state.toml")) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let state = Self::default();
                tracing::debug!(event = "state_loaded", path = %paths.state.join("state.toml").display(), exists = false,
                    state_json = %serde_json::to_string(&state)?);
                return Ok(state);
            }
            Err(e) => return Err(e.into()),
        };
        let state: Self = toml::from_str(&text).context("invalid seccy state.toml")?;
        // Reuse configuration validation for names and emails before filesystem access.
        for (name, record) in &state.keys {
            let config = Config {
                user: UserConfig {
                    email: record.email.clone(),
                },
                keys: [(name.clone(), KeyConfig { mode: record.mode })].into(),
            };
            Config::parse(&toml::to_string(&config)?)?;
            ensure!(
                record.config.is_absolute(),
                "state config path must be absolute"
            );
        }
        tracing::debug!(event = "state_loaded", path = %paths.state.join("state.toml").display(), exists = true,
            state_json = %serde_json::to_string(&state)?);
        Ok(state)
    }

    /// Caller holds the registry's exclusive lock.
    pub fn save(&self, paths: &Paths) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(&paths.state)?;
        file.write_all(toml::to_string_pretty(self)?.as_bytes())?;
        file.as_file().sync_all()?;
        file.persist(paths.state.join("state.toml"))?;
        fs::File::open(&paths.state)?.sync_all()?;
        tracing::debug!(event = "state_saved", path = %paths.state.join("state.toml").display(),
            state_json = %serde_json::to_string(self)?);
        Ok(())
    }

    pub fn overlay(&mut self, config: &Config, source: &Path) {
        for (name, key) in &config.keys {
            self.keys.entry(name.clone()).or_insert_with(|| Record {
                mode: key.mode,
                config: source.into(),
                email: config.user.email.clone(),
                public_key: None,
                fingerprint: None,
            });
        }
    }

    pub fn identity(&self, store: &impl KeyStore, name: &str) -> Result<Option<Identity>> {
        let Some(record) = self.keys.get(name) else {
            return Ok(None);
        };
        Ok(store.identity(name, record.mode)?.map(|i| {
            i.with_user(&UserConfig {
                email: record.email.clone(),
            })
        }))
    }

    pub fn info(
        &self,
        store: &impl KeyStore,
        paths: &Paths,
        name: &str,
    ) -> Result<Option<KeyInfo>> {
        let Some(record) = self.keys.get(name) else {
            return Ok(None);
        };
        let identity = self.identity(store, name)?;
        let mut info = KeyInfo::new(name, record.mode, identity.as_ref(), paths)?;
        info.config = Some(display_path(&record.config));
        Ok(Some(info))
    }
}

pub fn display_path(path: &Path) -> String {
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        let canonical = fs::canonicalize(&home).unwrap_or_else(|_| home.clone());
        if let Ok(relative) = path
            .strip_prefix(&home)
            .or_else(|_| path.strip_prefix(&canonical))
        {
            return format!("~/{}", relative.display());
        }
    }
    path.display().to_string()
}
