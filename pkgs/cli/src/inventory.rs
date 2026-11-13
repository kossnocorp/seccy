use crate::platform;
use crate::{Commands, server};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use seccy_core::{
    Config, KeyStore,
    state::{Record, State},
    storage::{KeyInfo, Paths, sync_public_key},
};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::{IsTerminal, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

type Stamp = (u64, u64, i64, i64, i64, i64);

fn emit(output: &crate::Output, value: serde_json::Value, text: &str) -> Result<()> {
    tracing::debug!(event = "inventory_result", result_json = %value);
    crate::emit(output, value, text)
}

fn log_view(state: &State, config: &Config, source: &Path) -> Result<()> {
    tracing::debug!(event = "inventory_view", config_path = %source.display(),
        config_json = %serde_json::to_string(config)?, state_json = %serde_json::to_string(state)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seccy_core::{Caller, Identity, Mode, payload::Payload};
    use std::{collections::BTreeMap, sync::Mutex};

    #[derive(Default)]
    struct Store(Mutex<BTreeMap<String, Identity>>);

    impl KeyStore for Store {
        fn create_generation(&self, name: &str, mode: Mode) -> Result<Identity> {
            Ok(self.provision(name, mode)?.0)
        }

        fn provision(&self, name: &str, mode: Mode) -> Result<(Identity, bool)> {
            let mut keys = self.0.lock().unwrap();
            if let Some(key) = keys.get(name) {
                return Ok((key.clone(), false));
            }
            // Fixed public P-256 generator; no hardware/private operations in this test.
            let hex = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
            let point = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>();
            let key = Identity::new(name, mode, &point)?;
            keys.insert(name.into(), key.clone());
            Ok((key, true))
        }

        fn identity(&self, name: &str, _: Mode) -> Result<Option<Identity>> {
            Ok(self.0.lock().unwrap().get(name).cloned())
        }

        fn sign(&self, _: &Identity, _: &[u8], _: &Caller, _: &Payload) -> Result<Vec<u8>> {
            unreachable!()
        }
    }

    #[cfg(target_os = "macos")]
    struct Generations(Store);
    #[cfg(target_os = "macos")]
    impl KeyStore for Generations {
        fn create_generation(&self, name: &str, mode: Mode) -> Result<Identity> {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let mut keys = self.0.0.lock().unwrap();
            let count = keys.len() as u8 + 1;
            let public = p256::SecretKey::from_slice(&[count; 32])?.public_key();
            let mut identity =
                Identity::new(name, mode, public.to_encoded_point(false).as_bytes())?;
            identity.storage_id = identity.key_id();
            keys.insert(identity.storage_id.clone(), identity.clone());
            Ok(identity)
        }
        fn provision(&self, name: &str, mode: Mode) -> Result<(Identity, bool)> {
            Ok((
                self.identity(name, mode)?.context("missing generation")?,
                false,
            ))
        }
        fn identity(&self, name: &str, mode: Mode) -> Result<Option<Identity>> {
            self.0.identity(name, mode)
        }
        fn sign(&self, _: &Identity, _: &[u8], _: &Caller, _: &Payload) -> Result<Vec<u8>> {
            unreachable!()
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn verification_is_pinned_and_rebuild_reads_new_policy() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
        fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        fs::create_dir_all(&paths.state).unwrap();
        let store = Generations(Store::default());
        let source = "[keys.auth]\nuse='ssh-auth'";
        fs::write(&paths.config, source).unwrap();
        let mut state = State::default();
        provision(
            &store,
            &Config::parse(source).unwrap(),
            &paths.config,
            &paths,
            &mut state,
        )
        .unwrap();
        assert_eq!(
            state.keys["auth"].pinned_policy().verify.as_deref(),
            Some("biometry-any")
        );
        // Old registries omitted verify: preserve current-set without silently replacing it.
        state
            .keys
            .get_mut("auth")
            .unwrap()
            .policy
            .as_mut()
            .unwrap()
            .verify = None;
        provision(
            &store,
            &Config::parse(source).unwrap(),
            &paths.config,
            &paths,
            &mut state,
        )
        .unwrap();
        assert_eq!(
            state.keys["auth"].pinned_policy().verify.as_deref(),
            Some("biometry-current-set")
        );
        let changed = format!("{source}\nverify='user-presence'");
        fs::write(&paths.config, &changed).unwrap();
        assert!(
            provision(
                &store,
                &Config::parse(&changed).unwrap(),
                &paths.config,
                &paths,
                &mut state
            )
            .is_err()
        );
        let (_, retired) = rebuild(&store, &mut state, "auth", None).unwrap();
        assert_eq!(
            state.keys["auth"].pinned_policy().verify.as_deref(),
            Some("user-presence")
        );
        assert_eq!(
            state.keys[&retired].pinned_policy().verify.as_deref(),
            Some("biometry-current-set")
        );
        assert!(state.identity(&store, "auth").unwrap().is_some());
        fs::write(&paths.config, source).unwrap();
        rebuild(&store, &mut state, "auth", None).unwrap();
        assert_eq!(
            state.keys["auth"].pinned_policy().verify.as_deref(),
            Some("biometry-any")
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn rebuild_reuses_alias_preserves_legacy_and_generations_and_supports_mode_change() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
        fs::create_dir_all(&paths.state).unwrap();
        let store = Generations(Store::default());
        let config = Config::parse(&format!(
            "provider='{}'\n[keys.auth]\nmode='prompt'",
            seccy_core::config::platform_kind()
        ))
        .unwrap();
        let mut state = State::default();
        provision(&store, &config, &paths.config, &paths, &mut state).unwrap();
        // Model a pre-generation installation: key physically stored under auth.
        let first = state.identity(&store, "auth").unwrap().unwrap();
        let mut legacy = first.clone();
        legacy.storage_id = "auth".into();
        store.0.0.lock().unwrap().remove(&first.storage_id);
        store.0.0.lock().unwrap().insert("auth".into(), legacy);
        let record = state.keys.get_mut("auth").unwrap();
        record.storage_id = None;
        record.secrets = true;
        let (second, retired) = rebuild(&store, &mut state, "auth", None).unwrap();
        assert_eq!(second.name, "auth");
        assert_ne!(first.fingerprint, second.fingerprint);
        assert!(state.keys[&retired].retired);
        assert!(state.keys[&retired].secrets);
        assert_eq!(state.keys[&retired].storage_id.as_deref(), Some("auth"));
        assert!(!state.keys["auth"].secrets);
        assert_eq!(
            state
                .identity(&store, &retired)
                .unwrap()
                .unwrap()
                .fingerprint,
            first.fingerprint
        );
        state.save(&paths).unwrap();
        state = State::load(&paths).unwrap();
        sync_public_key(&second, &paths).unwrap();
        assert_eq!(
            fs::read_to_string(paths.public_key("auth")).unwrap(),
            format!("{}\n", second.public_key)
        );
        assert!(paths.generation_public_key(&first).exists());
        assert!(paths.generation_public_key(&second).exists());
        let (third, retired_second) =
            rebuild(&store, &mut state, "auth", Some(Mode::Notify)).unwrap();
        assert_ne!(third.storage_id, second.storage_id);
        assert_eq!(third.mode, Mode::Notify);
        assert_eq!(
            state
                .identity(&store, &retired_second)
                .unwrap()
                .unwrap()
                .fingerprint,
            second.fingerprint
        );
        assert_eq!(state.keys.len(), 3);
        let before = serde_json::to_value(&state).unwrap();
        assert!(rebuild(&store, &mut state, &retired, None).is_err());
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
        // A missing physical key must never be silently replaced by provision.
        store.0.0.lock().unwrap().remove(&third.storage_id);
        assert!(
            provision(
                &store,
                &Config::default(),
                &paths.config,
                &paths,
                &mut state
            )
            .is_err()
        );
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
        // Reusing a removed alias must not reactivate a retained legacy key.
        state.keys.remove("auth");
        state.overlay(&config, &paths.config).unwrap();
        assert!(state.identity(&store, "auth").unwrap().is_none());
        provision(&store, &config, &paths.config, &paths, &mut state).unwrap();
        assert_ne!(state.keys["auth"].fingerprint, Some(first.fingerprint));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn rebuild_all_selects_active_keys_once_and_preserves_modes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
        fs::create_dir_all(&paths.state).unwrap();
        let store = Generations(Store::default());
        let config =
            Config::parse("[keys.auth]\nmode='prompt'\n[keys.signing]\nmode='notify'").unwrap();
        let mut state = State::default();
        provision(&store, &config, &paths.config, &paths, &mut state).unwrap();
        let (_, old) = rebuild(&store, &mut state, "auth", None).unwrap();
        let targets = rebuild_targets(&state, None).unwrap();
        assert_eq!(targets, ["auth", "signing"]);
        assert_eq!(
            rebuild_targets(&state, Some("signing")).unwrap(),
            ["signing"]
        );
        assert!(rebuild_targets(&state, Some(&old)).is_err());
        assert!(rebuild_targets(&state, Some("missing")).is_err());
        for name in targets {
            let mode = state.keys[&name].mode;
            let (identity, _) = rebuild(&store, &mut state, &name, None).unwrap();
            assert_eq!(identity.mode, mode);
            state.save(&paths).unwrap();
        }
        let loaded = State::load(&paths).unwrap();
        assert_eq!(loaded.keys.values().filter(|r| !r.retired).count(), 2);
        assert_eq!(loaded.keys.values().filter(|r| r.retired).count(), 3);
        assert!(rebuild_targets(&State::default(), None).unwrap().is_empty());
    }

    #[test]
    fn rebuild_creation_failure_keeps_original_binding() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
        fs::create_dir_all(&paths.state).unwrap();
        let store = Store::default();
        let config = Config::parse(&format!(
            "provider='{}'\n[keys.auth]\nmode='prompt'",
            seccy_core::config::platform_kind()
        ))
        .unwrap();
        let mut state = State::default();
        provision(&store, &config, &paths.config, &paths, &mut state).unwrap();
        let before = serde_json::to_value(&state).unwrap();
        // This fake store returns the same key: rebuild must reject it.
        assert!(rebuild(&store, &mut state, "auth", None).is_err());
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn policy_changes_fail_before_creation_and_permissions_cannot_expand_live() {
        use seccy_core::config::Use;
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
        fs::create_dir_all(&paths.state).unwrap();
        fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        let original = "[keys.auth]\nuse='ssh-auth'\n";
        fs::write(&paths.config, original).unwrap();
        let store = Store::default();
        let mut state = State::default();
        provision(
            &store,
            &Config::parse(original).unwrap(),
            &paths.config,
            &paths,
            &mut state,
        )
        .unwrap();
        let before = fs::read(paths.state.join("state.toml")).unwrap();
        // An earlier-sorted new key must not be created before discovering drift.
        let changed = "[keys.aaa]\nuse='ssh-auth'\n[keys.auth]\nmode='notify'\nuse='ssh-auth'\n";
        let error = provision(
            &store,
            &Config::parse(changed).unwrap(),
            &paths.config,
            &paths,
            &mut state,
        )
        .unwrap_err();
        assert!(error.to_string().contains("migration_required"));
        assert_eq!(store.0.lock().unwrap().len(), 1);
        assert_eq!(fs::read(paths.state.join("state.toml")).unwrap(), before);
        fs::write(&paths.config, "[keys.auth]\nuse=['ssh-auth','ssh-sign']\n").unwrap();
        let identity = state.identity(&store, "auth").unwrap().unwrap();
        assert!(identity.permits(Use::SshAuth));
        assert!(!identity.permits(Use::SshSign));
        fs::write(&paths.config, "[keys.auth]\nuse='ssh-sign'\n").unwrap();
        let identity = state.identity(&store, "auth").unwrap().unwrap();
        assert!(!identity.permits(Use::SshAuth));
        assert!(!identity.permits(Use::SshSign));
        fs::write(&paths.config, changed).unwrap();
        assert!(
            state
                .identity(&store, "auth")
                .unwrap_err()
                .to_string()
                .contains("migration_required")
        );
    }

    #[test]
    fn reprovision_persists_effective_emails_without_recreating_keys() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
        fs::create_dir_all(&paths.state).unwrap();
        let source = paths.config.clone();
        let store = Store::default();
        let mut config = Config::parse(
            "email='personal@example.com'\n[keys.personal]\nmode='notify'\n[keys.work]\nmode='prompt'\nemail='work@example.com'",
        )
        .unwrap();
        if cfg!(target_os = "linux") {
            config.provider = Some(seccy_core::config::Selector::Named("tpm-fido2-hmac".into()));
            config.keys.get_mut("personal").unwrap().mode = Some(Mode::Prompt);
        }
        let mut state = State::default();
        let output = provision(&store, &config, &source, &paths, &mut state).unwrap();
        assert!(output.iter().all(|entry| entry["created"] == true));
        let fingerprints = state
            .keys
            .iter()
            .map(|(name, record)| (name.clone(), record.fingerprint.clone()))
            .collect::<BTreeMap<_, _>>();

        // Exercise override changes, its removal, the name fallback, and an
        // override without a default. Reload persisted state on every operation.
        for (default, override_email, personal, work) in [
            (
                Some("personal@example.com"),
                Some("work@example.com"),
                "personal@example.com",
                "work@example.com",
            ),
            (
                Some("personal@example.com"),
                Some("new@example.com"),
                "personal@example.com",
                "new@example.com",
            ),
            (
                Some("personal@example.com"),
                None,
                "personal@example.com",
                "personal@example.com",
            ),
            (None, None, "personal", "work"),
            (
                None,
                Some("only@example.com"),
                "personal",
                "only@example.com",
            ),
        ] {
            config.email = default.map(str::to_owned);
            config.keys.get_mut("work").unwrap().email = override_email.map(str::to_owned);
            state = State::load(&paths).unwrap();
            let output = provision(&store, &config, &source, &paths, &mut state).unwrap();
            assert!(output.iter().all(|entry| entry["created"] == false));
            state = State::load(&paths).unwrap();
            for (name, comment) in [("personal", personal), ("work", work)] {
                assert_eq!(
                    state.keys[name].email.as_deref(),
                    config.effective_email(name)
                );
                assert_eq!(state.keys[name].fingerprint, fingerprints[name]);
                let identity = state.identity(&store, name).unwrap().unwrap();
                assert!(identity.public_key.ends_with(&format!(" {comment}")));
                assert_eq!(
                    state.keys[name].public_key.as_deref(),
                    Some(identity.public_key.as_str())
                );
                assert_eq!(
                    fs::read_to_string(paths.public_key(name)).unwrap(),
                    format!("{}\n", identity.public_key)
                );
                assert!(state.info(&store, &paths, name).unwrap().unwrap().synced);
            }

            // list/get and sync consume stored comments even when the current
            // configuration has changed, until provision explicitly updates it.
            let mut changed =
                Config::parse("email='ignored@example.com'\n[keys.work]\nmode='prompt'").unwrap();
            changed.provider = config.provider.clone();
            state.overlay(&changed, &source).unwrap();
            let identity = state.identity(&store, "work").unwrap().unwrap();
            assert!(identity.public_key.ends_with(&format!(" {work}")));
            fs::remove_file(paths.public_key("work")).unwrap();
            sync_public_key(&identity, &paths).unwrap();
            let info = state.info(&store, &paths, "work").unwrap().unwrap();
            assert!(info.synced);
            assert_eq!(info.public_key, Some(identity.public_key));
        }

        // No source config: provisioning must keep the registry's own emails.
        state = State::load(&paths).unwrap();
        provision(&store, &Config::default(), &source, &paths, &mut state).unwrap();
        assert_eq!(
            state.keys["work"].email.as_deref(),
            Some("only@example.com")
        );
        assert_eq!(state.keys["personal"].email, None);
        assert_eq!(store.0.lock().unwrap().len(), 2);
    }
}

#[derive(Default)]
pub struct Cached {
    state: std::sync::Mutex<Option<(Option<Stamp>, State)>>,
}

impl Cached {
    /// Keep the returned shared lock alive through the operation. Writers cannot
    /// remove/reprovision keys while an authorized operation is in flight.
    pub fn keys(&self, include_retired: bool) -> Result<(File, Vec<seccy_core::Identity>)> {
        use std::os::unix::fs::MetadataExt;
        let paths = Paths::from_env()?;
        let lock = read_lock(&paths)?;
        let stamp = match fs::metadata(paths.state.join("state.toml")) {
            Ok(m) => Some((
                m.ino(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let mut cached = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("state cache poisoned"))?;
        if cached.as_ref().is_none_or(|(old, _)| old != &stamp) {
            // Do not update the stamp on failure: subsequent requests also fail closed.
            *cached = Some((stamp, State::load(&paths)?));
        } else {
            tracing::debug!(event = "state_cache_hit", path = %paths.state.join("state.toml").display());
        }
        let state = &cached.as_ref().context("missing state cache")?.1;
        let keys = state
            .keys
            .iter()
            .filter(|(_, record)| include_retired || !record.retired)
            .map(|(name, _)| state.identity(&platform::Store, name))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok((lock, keys))
    }
}

pub fn read_lock(paths: &Paths) -> Result<File> {
    server::private_dir(&paths.state)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(paths.state.join("state.lock"))?;
    FileExt::lock_shared(&file)?;
    Ok(file)
}

pub fn view(paths: &Paths, config: &Config, source: &Path) -> Result<State> {
    let mut state = State::load(paths)?;
    let source = absolute_source(source)?;
    state.overlay(config, &source)?;
    log_view(&state, config, &source)?;
    Ok(state)
}

fn absolute_source(path: &Path) -> Result<std::path::PathBuf> {
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(std::path::absolute(path)?),
        Err(e) => Err(e.into()),
    }
}

pub fn confirm(yes: bool, message: &str) -> Result<()> {
    if yes {
        return Ok(());
    }
    ensure!(
        std::io::stdin().is_terminal(),
        "confirmation requires a terminal; pass -y or --yes"
    );
    eprint!("{message} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    ensure!(
        matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        "cancelled"
    );
    Ok(())
}

fn remove_public(paths: &Paths, name: &str) -> Result<()> {
    match fs::remove_file(paths.public_key(name)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn reported_info(
    state: &State,
    paths: &Paths,
    config: &Config,
    source: &Path,
    name: &str,
) -> Result<Option<KeyInfo>> {
    let mut info = state.info(&platform::Store, paths, name)?;
    if let Some(info) = &mut info
        && matches!(info.status, seccy_core::storage::KeyStatus::NotProvisioned)
        && config.keys.contains_key(name)
    {
        info.config = Some(seccy_core::state::display_path(source));
    }
    Ok(info)
}

fn provision(
    store: &impl KeyStore,
    config: &Config,
    source: &Path,
    paths: &Paths,
    state: &mut State,
) -> Result<Vec<serde_json::Value>> {
    let source = absolute_source(source)?;
    for (name, key) in &config.keys {
        let policy = config.resolve(name)?;
        policy.ensure_available()?;
        anyhow::ensure!(
            key.bind.is_none(),
            "existing machine providers do not accept portable bind"
        );
        if let Some(old) = state.keys.get(name) {
            ensure!(
                !old.retired,
                "configuration names a retired generation; use its active alias"
            );
            ensure!(
                old.mode == policy.mode && policy.matches_existing(&old.pinned_policy()),
                "migration_required: key {name} provider or mode changed; preserve the old key and migrate explicitly"
            );
        }
    }
    let mut targets = state.clone();
    targets.overlay(config, &source)?;
    log_view(&targets, config, &source)?;
    let mut output = Vec::new();
    for (name, record) in &targets.keys {
        if record.retired {
            continue;
        }
        let binding = record.storage_id.as_deref().unwrap_or(name);
        let legacy_is_retired = record.storage_id.is_none()
            && record.fingerprint.is_none()
            && state
                .keys
                .values()
                .any(|r| r.retired && r.storage_id.as_deref() == Some(name));
        let existing = if legacy_is_retired {
            None
        } else {
            store.identity(binding, record.mode)?
        };
        let creation_policy = if config.keys.contains_key(name) {
            config.resolve(name)?.for_creation()
        } else {
            record
                .policy
                .clone()
                .unwrap_or_else(|| record.pinned_policy())
                .for_creation()
        };
        let actual_policy = if existing.is_some() {
            let mut pinned = state.keys.get(name).unwrap_or(record).pinned_policy();
            if !state.keys.contains_key(name)
                && pinned.kind == "secure-enclave"
                && pinned.mode == seccy_core::Mode::Prompt
            {
                pinned.verify = Some("biometry-current-set".into());
            }
            if config.keys.contains_key(name) {
                ensure!(
                    config.resolve(name)?.matches_existing(&pinned),
                    "migration_required: existing key verification policy differs; use seccy rebuild {name}"
                );
            }
            pinned
        } else {
            creation_policy.clone()
        };
        let (identity, created) = if let Some(identity) = existing {
            ensure!(
                record
                    .fingerprint
                    .as_ref()
                    .is_none_or(|f| f == &identity.fingerprint),
                "key binding changed for {name}; refusing to use another key"
            );
            // Complete any backend-specific pending provisioning (not a replacement).
            store.provision(binding, record.mode)?
        } else {
            ensure!(
                record.fingerprint.is_none(),
                "key {name} is missing; use seccy rebuild {name} for explicit replacement"
            );
            (
                store.create_generation_with_policy(name, &creation_policy)?,
                true,
            )
        };
        let identity = identity.with_name(name);
        let email = if config.keys.contains_key(name) {
            config.effective_email(name).map(str::to_owned)
        } else {
            record.email.clone()
        };
        let identity = identity.with_email(email.as_deref());
        state.keys.insert(
            name.clone(),
            Record {
                display_name: config
                    .keys
                    .get(name)
                    .and_then(|k| k.name.clone())
                    .or_else(|| record.display_name.clone()),
                policy: Some(actual_policy),
                uses: config.keys.get(name).map_or_else(
                    || record.uses.clone(),
                    |k| k.uses.clone().or_else(|| record.uses.clone()),
                ),
                github_roles: config
                    .keys
                    .get(name)
                    .map(|k| k.github_roles())
                    .or_else(|| record.github_roles.clone()),
                secrets: record.secrets
                    && config
                        .keys
                        .get(name)
                        .and_then(|k| k.uses.as_ref())
                        .is_none_or(|u| u.0.contains(&seccy_core::config::Use::Secrets)),
                config: if config.keys.contains_key(name) {
                    source.clone()
                } else {
                    record.config.clone()
                },
                email,
                github: config
                    .keys
                    .get(name)
                    .map_or(record.github, |key| key.github),
                storage_id: Some(identity.storage_id.clone()),
                public_key: Some(identity.public_key.clone()),
                fingerprint: Some(identity.fingerprint.clone()),
                ..record.clone()
            },
        );
        // Persist each completed private-key operation, so retries can recover.
        state.save(paths)?;
        let updated = sync_public_key(&identity, paths)?;
        let info = state.info(store, paths, name)?;
        output.push(json!({"key": info, "created": created, "updated": updated}));
    }
    Ok(output)
}

fn rebuild_targets(state: &State, selected: Option<&str>) -> Result<Vec<String>> {
    let targets = match selected {
        Some(name) => vec![name.to_owned()],
        None => state
            .keys
            .iter()
            .filter(|(_, record)| !record.retired)
            .map(|(name, _)| name.clone())
            .collect(),
    };
    // Validate the entire selection before creating the first key.
    for name in &targets {
        let record = state.keys.get(name).context("key is not registered")?;
        ensure!(
            !record.retired,
            "cannot rebuild a retired generation; select its active alias"
        );
        let public = record
            .public_key
            .as_deref()
            .context("key has no recorded public identity")?;
        let old_id = seccy_core::identity_from_public(name, record.mode, public)?.key_id();
        ensure!(
            !state.keys.contains_key(&old_id),
            "retained generation ID conflicts with an existing registry entry"
        );
    }
    Ok(targets)
}

fn rebuild(
    store: &impl KeyStore,
    state: &mut State,
    name: &str,
    mode: Option<seccy_core::Mode>,
) -> Result<(seccy_core::Identity, String)> {
    let old = state
        .keys
        .get(name)
        .context("key is not registered")?
        .clone();
    ensure!(
        !old.retired,
        "cannot rebuild a retired generation; select its active alias"
    );
    let public = old
        .public_key
        .as_deref()
        .context("key has no recorded public identity")?;
    let old_id = seccy_core::identity_from_public(name, old.mode, public)?.key_id();
    ensure!(
        !state.keys.contains_key(&old_id),
        "retained generation ID conflicts with an existing registry entry"
    );
    let replacement_mode = mode.unwrap_or(old.mode);
    ensure!(
        replacement_mode != seccy_core::Mode::Notify
            || (seccy_core::config::platform_kind() == "secure-enclave"
                && old
                    .uses
                    .as_ref()
                    .is_none_or(|u| !u.0.contains(&seccy_core::config::Use::Secrets))),
        "notify mode is not supported for this provider or secrets usage"
    );
    let source_config = Config::load(&old.config)?;
    let mut policy = if source_config.keys.contains_key(name) {
        source_config.resolve(name)?
    } else {
        let mut policy = old.pinned_policy();
        policy.verify = None;
        policy
    };
    ensure!(
        policy.kind == old.pinned_policy().kind,
        "cross-provider rebuilding is not supported"
    );
    policy.mode = replacement_mode;
    ensure!(
        policy.mode != seccy_core::Mode::Notify || policy.verify.is_none(),
        "notify mode does not accept verify"
    );
    let policy = policy.for_creation();
    policy.ensure_available()?;
    let identity = store
        .create_generation_with_policy(name, &policy)?
        .with_name(name)
        .with_email(old.email.as_deref());
    ensure!(
        Some(&identity.fingerprint) != old.fingerprint.as_ref(),
        "backend did not create a fresh generation"
    );
    let mut retired = old.clone();
    retired.storage_id = Some(old.storage_id.clone().unwrap_or_else(|| name.into()));
    retired.retired = true;
    retired.alias = Some(name.into());
    let mut replacement = old;
    replacement.storage_id = Some(identity.storage_id.clone());
    replacement.mode = identity.mode;
    replacement.policy = Some(policy);
    replacement.public_key = Some(identity.public_key.clone());
    replacement.fingerprint = Some(identity.fingerprint.clone());
    replacement.secrets = false;
    state.keys.insert(old_id.clone(), retired);
    state.keys.insert(name.into(), replacement);
    Ok((identity, old_id))
}

pub fn run(
    command: Commands,
    config: &Config,
    source: &Path,
    paths: &Paths,
    output_mode: &crate::Output,
) -> Result<()> {
    match &command {
        Commands::Remove(args) => {
            ensure!(
                !args.name.is_empty()
                    && args.name.len() <= 64
                    && args
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
                "invalid key name"
            );
            confirm(
                args.yes,
                &format!(
                    "Permanently delete key {:?} and its public file?",
                    args.name
                ),
            )?;
        }
        Commands::Reset(args) => confirm(
            args.yes,
            "Permanently delete ALL seccy keys and registry entries?",
        )?,
        _ => (),
    }
    server::private_dir(&paths.state)?;
    let _lock = if matches!(command, Commands::List(_) | Commands::Get(_)) {
        read_lock(paths)?
    } else {
        server::lock(&paths.state.join("state.lock"))?
    };
    let store = platform::Store;
    let mut state = State::load(paths)?;
    match command {
        Commands::Rebuild(args) => {
            let mode = args
                .mode
                .as_deref()
                .map(|mode| match mode {
                    "prompt" => Ok(seccy_core::Mode::Prompt),
                    "notify" => Ok(seccy_core::Mode::Notify),
                    _ => anyhow::bail!("mode must be prompt or notify"),
                })
                .transpose()?;
            let targets = rebuild_targets(&state, args.name.as_deref())?;
            if targets.is_empty() {
                return emit(
                    output_mode,
                    json!({"ok":true,"keys":[]}),
                    "No active keys to rebuild",
                );
            }
            confirm(
                args.yes,
                &format!(
                    "Rebuild {} active key(s): {}? SSH/signing registrations must be updated. Old keys and ciphertext are preserved.",
                    targets.len(),
                    targets.join(", ")
                ),
            )?;
            let mut results = Vec::new();
            for name in &targets {
                let result = (|| -> Result<serde_json::Value> {
                    let (identity, retired) = rebuild(&store, &mut state, name, mode)?;
                    // Persist each completed generation. Later failures never
                    // undo an already completed replacement or delete old keys.
                    state.save(paths)?;
                    let retained = &state.keys[&retired];
                    let old_public = seccy_core::identity_from_public(
                        &retired, retained.mode,
                        retained.public_key.as_deref().context("missing retained public key")?,
                    )?.with_email(retained.email.as_deref());
                    sync_public_key(&old_public, paths)?;
                    sync_public_key(&identity, paths)?;
                    Ok(json!({"ok":true,"key":name,"storage_id":identity.storage_id,
                        "retired":retired,"public_key":identity.public_key,"fingerprint":identity.fingerprint}))
                })().with_context(|| format!(
                    "rebuild failed at {name}; completed keys: {}. Inspect seccy list and run seccy sync if needed; rebuild remaining keys by name to avoid rotating completed keys again",
                    results.iter().filter_map(|v: &serde_json::Value| v["key"].as_str()).collect::<Vec<_>>().join(", ")
                ))?;
                results.push(result);
            }
            let value = if args.name.is_some() {
                results.remove(0)
            } else {
                json!({"ok":true,"keys":results})
            };
            emit(
                output_mode,
                value,
                &format!(
                    "Rebuilt {}. Old generations retained. Update SSH/signing registrations (seccy gh sync for GitHub). Enroll replacement recipients, then reencrypt from working keys or use secrets reset.",
                    targets.join(", ")
                ),
            )?;
        }

        Commands::Provision(_) => {
            let output = provision(&store, config, source, paths, &mut state)?;
            emit(
                output_mode,
                json!({"ok": true, "keys": output}),
                "Keys provisioned and public files synced",
            )?;
        }
        Commands::List(_) | Commands::Get(_) | Commands::Sync(_) => {
            let source = absolute_source(source)?;
            state.overlay(config, &source)?;
            log_view(&state, config, &source)?;
            if let Commands::Get(args) = command {
                let info = reported_info(&state, paths, config, &source, &args.name)?;
                let text = info.as_ref().map(KeyInfo::text).unwrap_or_default();
                emit(output_mode, json!({"ok": true, "key": info}), &text)?;
            } else {
                let mut output = Vec::new();
                let mut text = Vec::new();
                for name in state.keys.keys() {
                    let mut updated = false;
                    if matches!(command, Commands::Sync(_))
                        && let Some(identity) = state.identity(&store, name)?
                    {
                        updated = sync_public_key(&identity, paths)?;
                    }
                    let info = reported_info(&state, paths, config, &source, name)?
                        .context("key disappeared")?;
                    text.push(info.text());
                    output.push(if matches!(command, Commands::Sync(_)) {
                        json!({"key": info, "updated": updated})
                    } else {
                        json!(info)
                    });
                }
                if !text.is_empty() {
                    text.insert(0, "Name\tMode\tStatus\tPublic file\tPath\tConfig".into());
                }
                emit(
                    output_mode,
                    json!({"ok": true, "keys": output}),
                    &text.join("\n"),
                )?;
            }
        }
        Commands::Remove(args) => {
            if let Some(record) = state.keys.get(&args.name) {
                if let Some(public) = &record.public_key {
                    let identity =
                        seccy_core::identity_from_public(&args.name, record.mode, public)?;
                    let file = paths.generation_public_key(&identity);
                    match fs::remove_file(file) {
                        Ok(()) => (),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                        Err(e) => return Err(e.into()),
                    }
                }
                store.remove(record.storage_id.as_deref().unwrap_or(&args.name))?;
            } else {
                ensure!(
                    !state
                        .keys
                        .values()
                        .any(|r| r.storage_id.as_deref() == Some(&args.name)),
                    "this physical key is retained under another registry entry; remove that generation explicitly"
                );
                store.remove(&args.name)?;
            }
            remove_public(paths, &args.name)?;
            state.keys.remove(&args.name);
            state.save(paths)?;
            emit(
                output_mode,
                json!({"ok": true, "removed": args.name}),
                "Key removed",
            )?;
        }
        Commands::Reset(_) => {
            let mut names: std::collections::BTreeSet<_> = state.keys.keys().cloned().collect();
            names.extend(
                state
                    .keys
                    .values()
                    .filter_map(|record| record.storage_id.clone()),
            );
            names.extend(store.managed_names()?);
            match fs::read_dir(&paths.keys) {
                Ok(entries) => {
                    for entry in entries {
                        let path = entry?.path();
                        if path.extension().is_some_and(|e| e == "pub")
                            && let Some(name) = path.file_stem().and_then(|n| n.to_str())
                            && !name.is_empty()
                            && name
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                        {
                            names.insert(name.into());
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
            for name in names {
                store.remove(&name)?;
                remove_public(paths, &name)?;
                state.keys.remove(&name);
                state.save(paths)?;
            }
            state.save(paths)?;
            let generations = paths.keys.join("generations");
            if generations.is_dir() {
                for entry in fs::read_dir(&generations)? {
                    let path = entry?.path();
                    if path.extension().is_some_and(|e| e == "pub") {
                        fs::remove_file(path)?;
                    }
                }
            }
            emit(
                output_mode,
                json!({"ok": true}),
                "All seccy keys and registry entries removed",
            )?;
        }
        _ => unreachable!(),
    }
    Ok(())
}
