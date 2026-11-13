//! Persistent inventory with pinned policies and live permission narrowing.
use crate::{
    Config, Identity, KeyStore, Mode,
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
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub policy: Option<crate::config::Resolved>,
    #[serde(default, rename = "use")]
    pub uses: Option<crate::config::Many<crate::config::Use>>,
    #[serde(default)]
    pub github_roles: Option<Vec<crate::Github>>,
    /// Explicit local consent to use this key for managed secrets.
    #[serde(default)]
    pub secrets: bool,
    pub mode: Mode,
    pub github: Option<crate::Github>,
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
            crate::config::validate_email(record.email.as_deref(), "registry email")?;
            ensure!(
                crate::config::valid_handle(name),
                "invalid registry key name"
            );
            if let Some(policy) = &record.policy {
                ensure!(policy.mode == record.mode, "registry policy/mode mismatch");
                ensure!(
                    policy.kind == crate::config::platform_kind(),
                    "registry provider does not match this platform"
                );
            }
            if let Some(uses) = &record.uses {
                ensure!(!uses.0.is_empty(), "registry use must not be empty");
                ensure!(
                    !record.secrets || uses.0.contains(&crate::config::Use::Secrets),
                    "registry secrets permission mismatch"
                );
            }
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

    pub fn overlay(&mut self, config: &Config, source: &Path) -> Result<()> {
        for (name, key) in &config.keys {
            let policy = config.resolve(name)?;
            policy.ensure_available()?;
            self.keys.entry(name.clone()).or_insert_with(|| Record {
                display_name: key.name.clone(),
                policy: Some(policy.clone()),
                uses: key.uses.clone(),
                github_roles: Some(key.github_roles()),
                secrets: false,
                mode: policy.mode,
                github: key.github,
                config: source.into(),
                email: config.effective_email(name).map(str::to_owned),
                public_key: None,
                fingerprint: None,
            });
        }
        Ok(())
    }

    pub fn identity(&self, store: &impl KeyStore, name: &str) -> Result<Option<Identity>> {
        let Some(record) = self.keys.get(name) else {
            return Ok(None);
        };
        let config = Config::load(&record.config)?;
        let mut uses = record.uses.clone();
        if let Some(key) = config.keys.get(name) {
            let policy = config.resolve(name)?;
            policy.ensure_available()?;
            ensure!(
                policy.mode == record.mode
                    && record.policy.as_ref().is_none_or(|old| old == &policy),
                "migration_required: provider policy changed for {name}"
            );
            if let Some(requested) = &key.uses {
                uses = Some(crate::config::Many(
                    requested
                        .0
                        .iter()
                        .copied()
                        .filter(|u| record.uses.as_ref().is_none_or(|old| old.0.contains(u)))
                        .collect(),
                ));
            }
        }
        Ok(store.identity(name, record.mode)?.map(|mut i| {
            i.uses = uses;
            i.display_name = record.display_name.clone();
            i.with_email(record.email.as_deref())
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
        info.secrets = record.secrets;
        info.provider = record.policy.clone();
        info.uses = record.uses.clone();
        info.display_name = record.display_name.clone();
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
