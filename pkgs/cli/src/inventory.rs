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

#[derive(Default)]
pub struct Cached {
    state: std::sync::Mutex<Option<(Option<Stamp>, State)>>,
}

impl Cached {
    /// Keep the returned shared lock alive through the operation. Writers cannot
    /// remove/reprovision keys while an authorized operation is in flight.
    pub fn keys(&self) -> Result<(File, Vec<seccy_core::Identity>)> {
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
            .keys()
            .map(|name| state.identity(&seccy_macos::SecureEnclave, name))
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
    state.overlay(config, &source);
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

fn confirm(yes: bool, message: &str) -> Result<()> {
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
    let mut info = state.info(&seccy_macos::SecureEnclave, paths, name)?;
    if let Some(info) = &mut info
        && matches!(info.status, seccy_core::storage::KeyStatus::NotProvisioned)
        && config.keys.contains_key(name)
    {
        info.config = Some(seccy_core::state::display_path(source));
    }
    Ok(info)
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
    let store = seccy_macos::SecureEnclave;
    let mut state = State::load(paths)?;
    match command {
        Commands::Provision(_) => {
            let source = absolute_source(source)?;
            for (name, key) in &config.keys {
                if let Some(old) = state.keys.get(name) {
                    ensure!(
                        old.config == source,
                        "key {name} belongs to {}; remove it before using another config",
                        old.config.display()
                    );
                    ensure!(
                        old.mode == key.mode,
                        "key {name} mode changed; remove it before reprovisioning"
                    );
                }
            }
            let mut targets = state.clone();
            targets.overlay(config, &source);
            log_view(&targets, config, &source)?;
            let mut output = Vec::new();
            for (name, record) in &targets.keys {
                let (identity, created) = store.provision(name, record.mode)?;
                let email = if config.keys.contains_key(name) {
                    config.user.email.clone()
                } else {
                    record.email.clone()
                };
                let identity = identity.with_user(&seccy_core::UserConfig {
                    email: email.clone(),
                });
                state.keys.insert(
                    name.clone(),
                    Record {
                        email,
                        public_key: Some(identity.public_key.clone()),
                        fingerprint: Some(identity.fingerprint.clone()),
                        ..record.clone()
                    },
                );
                // Persist each completed private-key operation, so retries can recover.
                state.save(paths)?;
                let updated = sync_public_key(&identity, paths)?;
                let info = state.info(&store, paths, name)?;
                output.push(json!({"key": info, "created": created, "updated": updated}));
            }
            emit(
                output_mode,
                json!({"ok": true, "keys": output}),
                "Keys provisioned and public files synced",
            )?;
        }
        Commands::List(_) | Commands::Get(_) | Commands::Sync(_) => {
            let source = absolute_source(source)?;
            state.overlay(config, &source);
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
            store.remove(&args.name)?;
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
