//! Managed secrets CLI. Plaintext is never logged or written to a temporary file.
use crate::secret_args::*;
use crate::{
    Output,
    secret_config::{Config, Secret},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use seccy_core::{Mode, envelope, state::State, storage::Paths};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::{IsTerminal, Read, Write},
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt, process::CommandExt},
    process::Command,
};
use zeroize::Zeroizing;

fn choose(items: &[String], label: &str, output: &Output) -> Result<String> {
    let index = crate::selection::choose(items, label, output)?;
    Ok(items[index].clone())
}
fn hidden() -> Result<Zeroizing<Vec<u8>>> {
    use std::os::fd::AsRawFd;
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("secret input requires a terminal; use --from-stdin or --from-file")?;
    ensure!(tty.is_terminal(), "secret input requires a terminal");
    let fd = tty.as_raw_fd();
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    ensure!(
        unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } == 0,
        "cannot read terminal settings"
    );
    let original = unsafe { original.assume_init() };
    struct Restore(i32, libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.0, libc::TCSAFLUSH, &self.1);
            }
        }
    }
    let _restore = Restore(fd, original);
    let mut noecho = original;
    noecho.c_lflag &= !(libc::ECHO | libc::ECHONL);
    // Read control-C as a byte so cleanup restores echo before returning.
    noecho.c_lflag &= !(libc::ISIG | libc::ICANON);
    noecho.c_cc[libc::VMIN] = 1;
    noecho.c_cc[libc::VTIME] = 0;
    ensure!(
        unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &noecho) } == 0,
        "cannot disable terminal echo"
    );
    write!(tty, "Secret: ")?;
    tty.flush()?;
    let mut value = Zeroizing::new(Vec::new());
    loop {
        let mut b = [0];
        tty.read_exact(&mut b)?;
        match b[0] {
            b'\r' | b'\n' => break,
            3 | 4 | 26 => anyhow::bail!("secret input cancelled"),
            8 | 127 => {
                value.pop();
            }
            b => {
                ensure!(value.len() < envelope::MAX_SECRET, "secret exceeds 64 KiB");
                value.push(b);
            }
        }
    }
    writeln!(tty)?;
    Ok(value)
}
fn read_secret(reader: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(envelope::MAX_SECRET as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= envelope::MAX_SECRET, "secret exceeds 64 KiB");
    Ok(bytes)
}
fn recipients(config: &Config, selected: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let names = if selected.is_empty() {
        config.recipients.keys().cloned().collect()
    } else {
        selected.to_vec()
    };
    ensure!(
        !names.is_empty(),
        "no recipients; use secrets enroll or recipients add first"
    );
    let distinct: BTreeSet<_> = names.iter().collect();
    ensure!(
        distinct.len() == names.len(),
        "duplicate recipient selection"
    );
    let public = names
        .iter()
        .map(|name| {
            config
                .recipients
                .get(name)
                .cloned()
                .with_context(|| format!("unknown recipient {name}"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((names, public))
}
fn enrollment_candidates(state: &State) -> Vec<String> {
    state
        .keys
        .iter()
        .filter(|(_, record)| !record.retired && record.mode == Mode::Prompt)
        .map(|(name, _)| name.clone())
        .collect()
}

fn check_configured_identity(config: &seccy_core::Config, state: &State, name: &str) -> Result<()> {
    let record = state.keys.get(name);
    let alias = record.and_then(|r| r.alias.as_deref()).unwrap_or(name);
    if let Some(key) = config.keys.get(alias) {
        ensure!(
            key.uses
                .as_ref()
                .is_none_or(|u| u.0.contains(&seccy_core::config::Use::Secrets)),
            "key use does not permit secrets"
        );
        // Retired generations retain their creation policy. New policy settings
        // on the active alias must not make old ciphertext inaccessible.
        if !record.is_some_and(|r| r.retired) {
            let policy = config.resolve(alias)?;
            policy.ensure_available()?;
            if let Some(record) = record {
                ensure!(
                    record.mode == policy.mode && policy.matches_existing(&record.pinned_policy()),
                    "migration_required: selected config does not match enrolled identity"
                );
            }
        }
    }
    Ok(())
}

fn decrypt(
    name: &str,
    secret: &Secret,
    selected: Option<&str>,
    key_config: &seccy_core::Config,
) -> Result<Zeroizing<Vec<u8>>> {
    let paths = Paths::from_env()?;
    let _lock = crate::inventory::read_lock(&paths)?;
    let state = State::load(&paths)?;
    let envelope = envelope::Envelope::parse(&secret.value, name)?;
    let identity = select_identity(&state, &envelope, selected)?;
    check_configured_identity(key_config, &state, &identity)?;
    drop(_lock);
    let mut response = crate::secrets::request(
        None,
        "decrypt-managed",
        &identity,
        Some(serde_json::to_string(
            &json!({"name": name, "value": secret.value}),
        )?),
    )?;
    let encoded = response["value_base64"]
        .as_str()
        .context("invalid decryption response")?;
    let result = Zeroizing::new(B64.decode(encoded)?);
    // Erase the owned base64 response before releasing it.
    if let serde_json::Value::String(s) = &mut response["value_base64"] {
        zeroize::Zeroize::zeroize(s);
    }
    Ok(result)
}
fn exec_marker(slot: &str) -> String {
    format!("__SECCY_{slot}__")
}

fn alias_marker(source: &str, slot: &str, fingerprint: &str, value: &OsStr) -> String {
    // Bind the check to this encrypted definition and slot, including non-UTF-8 values.
    let prefix = format!("alias:{source}:{fingerprint}:");
    let check = Sha256::new()
        .chain_update(&prefix)
        .chain_update(slot)
        .chain_update([0])
        .chain_update(value.as_bytes())
        .finalize();
    format!("{prefix}{check:x}")
}

// Index only alias markers. A plain marker always describes its own slot.
fn inherited_aliases() -> BTreeMap<String, Vec<(String, String)>> {
    let mut aliases = BTreeMap::new();
    for (key, marker) in std::env::vars_os() {
        let Some(slot) = key
            .to_str()
            .and_then(|k| k.strip_prefix("__SECCY_"))
            .and_then(|k| k.strip_suffix("__"))
            .filter(|k| envelope::valid_name(k))
        else {
            continue;
        };
        let Some((source, _)) = marker
            .to_str()
            .and_then(|m| m.strip_prefix("alias:"))
            .and_then(|m| m.split_once(':'))
        else {
            continue;
        };
        aliases
            .entry(source.to_owned())
            .or_insert_with(Vec::new)
            .push((slot.to_owned(), marker.into_string().unwrap()));
    }
    aliases
}

struct ExecSource<'a> {
    name: &'a str,
    fingerprint: String,
    slots: Vec<&'a str>,
}

impl ExecSource<'_> {
    fn inherited(&self, aliases: &BTreeMap<String, Vec<(String, String)>>) -> Option<OsString> {
        if std::env::var_os(exec_marker(self.name)).as_deref()
            == Some(OsStr::new(&self.fingerprint))
            && let Some(value) = std::env::var_os(self.name)
        {
            return Some(value);
        }
        aliases.get(self.name)?.iter().find_map(|(slot, marker)| {
            let value = std::env::var_os(slot)?;
            (alias_marker(self.name, slot, &self.fingerprint, &value) == *marker).then_some(value)
        })
    }

    fn export(&self, child: &mut Command, value: &OsStr) {
        for &slot in &self.slots {
            let marker = if slot == self.name {
                self.fingerprint.clone()
            } else {
                alias_marker(self.name, slot, &self.fingerprint, value)
            };
            child.env(slot, value).env(exec_marker(slot), marker);
        }
    }
}

fn decrypt_batch(
    names: &[String],
    config: &Config,
    selected: Option<&str>,
    key_config: &seccy_core::Config,
) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let paths = Paths::from_env()?;
    let lock = crate::inventory::read_lock(&paths)?;
    let state = State::load(&paths)?;
    let mut entries = Vec::new();
    for name in names {
        let secret = &config.secrets[name];
        let envelope = envelope::Envelope::parse(&secret.value, name)?;
        let identity = select_identity(&state, &envelope, selected)?;
        check_configured_identity(key_config, &state, &identity)?;
        entries.push(json!({"key": identity, "name": name, "value": secret.value}));
    }
    drop(lock);
    let mut response = crate::secrets::request(
        None,
        "decrypt-managed-batch",
        entries[0]["key"].as_str().unwrap(),
        Some(serde_json::to_string(&entries)?),
    )?;
    let values = response["values_base64"]
        .as_array_mut()
        .context("invalid batch decryption response")?;
    ensure!(
        values.len() == names.len(),
        "invalid batch decryption response"
    );
    let mut result = Vec::new();
    for value in values.iter_mut() {
        let encoded = value
            .as_str()
            .context("invalid batch decryption response")?;
        result.push(Zeroizing::new(B64.decode(encoded)?));
        if let serde_json::Value::String(s) = value {
            zeroize::Zeroize::zeroize(s);
        }
    }
    Ok(result)
}
pub fn run(
    mut args: SecretsArgs,
    paths: &Paths,
    global: &std::path::Path,
    output: &Output,
) -> Result<()> {
    // Resolve the logical key handle once, independently of the storage backend.
    // An explicit selection must never fall back to another identity.
    match std::env::var("SECCY_IDENTITY") {
        Ok(identity) => args.identity = Some(identity),
        Err(std::env::VarError::NotPresent) => (),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("SECCY_IDENTITY must contain a valid UTF-8 key handle")
        }
    }
    if let Some(identity) = &args.identity {
        ensure!(
            !identity.trim().is_empty(),
            "identity key handle must not be empty"
        );
    }

    let key_config = seccy_core::Config::load(&paths.config)?;
    if let Some(selected) = args.identity.as_deref()
        && matches!(
            args.command,
            SecretsCommand::Get(_) | SecretsCommand::Exec(_) | SecretsCommand::Reencrypt(_)
        )
        && key_config.keys.contains_key(selected)
    {
        key_config.resolve(selected)?.ensure_available()?;
    }
    let cwd = std::env::current_dir()?;
    let mutation = matches!(
        args.command,
        SecretsCommand::Set(_)
            | SecretsCommand::Enroll(_)
            | SecretsCommand::Reencrypt(_)
            | SecretsCommand::Reset(_)
            | SecretsCommand::Remove(_)
            | SecretsCommand::Recipients(RecipientArgs {
                command: RecipientCommand::Add(_) | RecipientCommand::Remove(_)
            })
    );
    ensure!(
        !(args.global && args.file.is_some()),
        "--global and --secrets are mutually exclusive"
    );
    if mutation && args.file.is_none() {
        let mut detected = crate::secret_config::detected_files(global, &cwd)?;
        if args.global {
            let family = crate::secret_config::global_files(global);
            detected.retain(|p| family.contains(p));
        }
        detected.reverse(); // closest project first, global last
        if detected.len() > 1 {
            ensure!(
                !output.structured(),
                "multiple secrets files found; select one with --secrets (-s) or --global (-g)"
            );
            let labels = detected
                .iter()
                .map(|p| crate::secret_config::file_label(p))
                .collect::<Vec<_>>();
            let index = crate::selection::choose(
                &labels,
                "secrets file (--secrets/-s or --global/-g)",
                output,
            )?;
            // Exactly the same isolated scope as an explicit --secrets selection.
            args.file = Some(detected[index].clone());
            args.global = false;
        }
    }
    let mut config = Config::load(global, &cwd, args.file.as_deref(), args.global)?;
    let _file_lock = if mutation {
        let parent = config.target.parent().context("invalid secrets path")?;
        if crate::secret_config::global_files(global).contains(&config.target) {
            crate::secret_config::config_dir(parent)?;
        }
        let lock = crate::secret_config::writer_lock(&paths.state, &config.target)?;
        // Reload after locking so concurrent Seccy writers cannot overwrite each other.
        config = Config::load(global, &cwd, args.file.as_deref(), args.global)?;
        Some(lock)
    } else {
        None
    };
    match args.command {
        SecretsCommand::List(_) => {
            let entries: Vec<_> = config.secrets.iter().map(|(name,s)| json!({"name":name,"recipients":s.recipients,"source":config.origins[name]})).collect();
            output.emit(
                json!({"ok":true,"file":config.target,"secrets":entries}),
                &config
                    .secrets
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n"),
            )?;
        }
        SecretsCommand::Set(set) => {
            ensure!(
                !(set.from_stdin && set.from_file.is_some()),
                "--from-stdin and --from-file are mutually exclusive"
            );
            let name = match set.name {
                Some(n) => n,
                None => choose(
                    &config.secrets.keys().cloned().collect::<Vec<_>>(),
                    "secret",
                    output,
                )?,
            };
            ensure!(
                envelope::valid_name(&name),
                "invalid secret name; use an environment variable name"
            );
            ensure!(
                config.secrets.contains_key(&name) || config.secrets.len() < 1024,
                "at most 1024 secrets are supported"
            );
            let (names, public) = recipients(&config, &set.recipient)?;
            let plaintext = if let Some(file) = set.from_file {
                let f = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(file)?;
                ensure!(f.metadata()?.is_file(), "input must be a regular file");
                read_secret(f)?
            } else if set.from_stdin {
                read_secret(std::io::stdin().lock())?
            } else {
                hidden()?
            };
            let value =
                envelope::encrypt(&name, &plaintext, &public, seccy_macos::wrap_secret_key)?;
            config.put_secret(
                &name,
                &Secret {
                    recipients: names.clone(),
                    value,
                },
            );
            config.save()?;
            output.emit(
                json!({"ok":true,"name":name,"recipients":names,"file":config.target}),
                &format!("Saved {name}"),
            )?;
        }
        SecretsCommand::Get(get) => {
            let secret = config.secrets.get(&get.name).context("secret not found")?;
            let value = decrypt(&get.name, secret, args.identity.as_deref(), &key_config)?;
            if output.structured() {
                output.emit(
                    json!({"ok":true,"name":get.name,"value_base64":B64.encode(&*value)}),
                    "",
                )?;
            } else {
                std::io::stdout().write_all(&value)?;
            }
        }
        SecretsCommand::Exec(exec) => {
            ensure!(
                !output.structured(),
                "exec streams the child process; --json and --jq are not supported"
            );
            let raw: Vec<_> = std::env::args_os().collect();
            let boundary = raw
                .iter()
                .position(|s| s == "--")
                .context("exec requires -- before the command")?;
            let command = &raw[boundary + 1..];
            ensure!(!command.is_empty(), "exec requires a command");
            ensure!(exec.args.len() >= command.len(), "invalid exec arguments");
            let names = &exec.args[..exec.args.len() - command.len()];
            let names: Vec<_> = if names.is_empty() {
                config.secrets.keys().cloned().collect()
            } else {
                names.to_vec()
            };
            let mut destinations = BTreeSet::new();
            let mut sources = BTreeMap::new();
            let mut order = Vec::new();
            for spec in &names {
                let (name, slot) = spec.split_once(':').unwrap_or((spec, spec));
                for part in [name, slot] {
                    ensure!(
                        envelope::valid_name(part),
                        "invalid environment variable name in binding {spec}"
                    );
                    ensure!(
                        !(part.starts_with("__SECCY_") && part.ends_with("__")),
                        "{part} uses the reserved exec fingerprint namespace __SECCY_*__"
                    );
                }
                let secret = config
                    .secrets
                    .get(name)
                    .with_context(|| format!("unknown secret {name}"))?;
                ensure!(
                    destinations.insert(slot),
                    "duplicate exec destination {slot}"
                );
                sources
                    .entry(name)
                    .or_insert_with(|| {
                        order.push(name);
                        ExecSource {
                            name,
                            fingerprint: format!("sha256:{:x}", Sha256::digest(&secret.value)),
                            slots: Vec::new(),
                        }
                    })
                    .slots
                    .push(slot);
            }
            let mut child = Command::new(&command[0]);
            child.args(&command[1..]);
            let mut pending = Vec::new();
            let aliases = inherited_aliases();
            for name in order {
                let source = &sources[name];
                if let Some(value) = source.inherited(&aliases) {
                    source.export(&mut child, &value);
                } else {
                    pending.push(name.to_owned());
                }
            }
            let values = decrypt_batch(&pending, &config, args.identity.as_deref(), &key_config)?;
            for (name, bytes) in pending.iter().zip(values) {
                ensure!(
                    !bytes.contains(&0),
                    "secret {name} contains NUL and cannot be an environment value"
                );
                sources[name.as_str()].export(&mut child, OsStr::from_bytes(&bytes));
            }
            // exec preserves child exit codes/signals and doesn't expose secrets in argv.
            return Err(child.exec()).context("execute command with secrets");
        }
        SecretsCommand::Enroll(enroll) => {
            crate::server::private_dir(&paths.state)?;
            let _lock = crate::server::lock(&paths.state.join("state.lock"))?;
            let mut state = State::load(paths)?;
            let candidates = enrollment_candidates(&state);
            let key = match enroll.key {
                Some(k) => k,
                None => choose(&candidates, "prompt key", output)?,
            };
            check_configured_identity(&key_config, &state, &key)?;
            let record = state
                .keys
                .get(&key)
                .context("key is not registered; provision it first")?;
            ensure!(
                record.mode == Mode::Prompt,
                "managed secrets require a prompt key"
            );
            let identity = state
                .identity(&seccy_macos::SecureEnclave, &key)?
                .context("key is not provisioned")?;
            ensure!(
                identity.permits(seccy_core::config::Use::Secrets),
                "key use does not permit secrets enrollment"
            );
            let configured = seccy_core::Config::load(&paths.config)?;
            if let Some(k) = configured.keys.get(&key) {
                configured.resolve(&key)?.ensure_available()?;
                ensure!(
                    k.uses
                        .as_ref()
                        .is_none_or(|u| u.0.contains(&seccy_core::config::Use::Secrets)),
                    "key use does not permit secrets enrollment"
                );
            }
            seccy_macos::SecureEnclave.crypto_check(&identity)?;
            let public = envelope::from_identity(&identity)?;
            let alias = enroll.name.unwrap_or_else(|| {
                if config
                    .recipients
                    .get(&key)
                    .is_some_and(|old| old != &public)
                {
                    identity.key_id()
                } else {
                    key.clone()
                }
            });
            config.put_recipient(&alias, &public)?;
            state.keys.get_mut(&key).unwrap().secrets = true;
            // Enrollment is idempotent; a failed config write can be retried safely.
            state.save(paths)?;
            config.save()?;
            output.emit(json!({"ok":true,"key":key,"name":alias,"recipient":public,"fingerprint":identity.fingerprint,"file":config.target}), &format!("Recipient {alias}: {public}"))?;
        }
        SecretsCommand::Reset(reset) => {
            ensure!(
                reset.from_env.is_none() || reset.name.is_some(),
                "--from-env requires a secret name"
            );
            ensure!(
                !reset.recipient.is_empty(),
                "select replacement recipients explicitly with --recipient; enroll a new key first"
            );
            let (names, public) = recipients(&config, &reset.recipient)?;
            let active = reset_targets(&config, reset.name.as_deref())?;
            ensure!(!active.is_empty(), "no secrets in active file");
            let mut env_value = reset.from_env.as_deref().map(secret_from_env).transpose()?;
            crate::inventory::confirm(
                reset.yes,
                &format!(
                    "Replace {} secret values in {}? Existing values will not be recovered. Check the file for other recipients and try reencrypt on a working recipient machine first.",
                    active.len(),
                    config.target.display()
                ),
            )?;
            reset_values(
                &mut config,
                &active,
                &names,
                &public,
                |name| {
                    if let Some(value) = env_value.take() {
                        return Ok(value);
                    }
                    eprintln!("Enter replacement value for {name}:");
                    hidden()
                },
                seccy_macos::wrap_secret_key,
            )?;
            output.emit(
                json!({"ok":true,"count":active.len(),"file":config.target,"recipients":names}),
                &format!("Replaced and encrypted {} secrets", active.len()),
            )?;
        }
        SecretsCommand::Reencrypt(selection) => {
            let (names, public) = recipients(&config, &selection.recipient)?;
            let active: Vec<_> = config
                .secrets
                .iter()
                .filter(|(n, _)| config.origins[*n] == config.target)
                .map(|(n, s)| (n.clone(), s.clone()))
                .collect();
            // All decryptions and encryptions succeed before the single atomic replacement.
            for (name, secret) in &active {
                let clear = decrypt(name, secret, args.identity.as_deref(), &key_config).with_context(|| format!(
                    "cannot recover {name}; check this file for other recipients. On a working recipient machine, add/enroll the new public recipient and reencrypt. If none can decrypt, enroll a replacement and run secrets reset --recipient <new-alias> to re-enter values"
                ))?;
                let value = envelope::encrypt(name, &clear, &public, seccy_macos::wrap_secret_key)?;
                config.put_secret(
                    name,
                    &Secret {
                        recipients: names.clone(),
                        value,
                    },
                );
            }
            config.save()?;
            output.emit(
                json!({"ok":true,"count":active.len(),"file":config.target,"recipients":names}),
                &format!("Re-encrypted {} secrets", active.len()),
            )?;
        }
        SecretsCommand::Remove(remove) => {
            ensure!(
                config.origins.get(&remove.name) == Some(&config.target),
                "secret is not defined in active file; use --secrets or --global"
            );
            config.target_doc()["secrets"]
                .as_table_like_mut()
                .context("missing secrets table")?
                .remove(&remove.name);
            config.save()?;
            output.emit(
                json!({"ok":true,"name":remove.name,"file":config.target}),
                "Secret removed (an inherited definition may now be visible)",
            )?;
        }
        SecretsCommand::Recipients(recipient) => match recipient.command {
            RecipientCommand::List(_) => {
                let entries = config.recipients.iter().map(|(name,key)|Ok(json!({"name":name,"recipient":key,"fingerprint":envelope::fingerprint(key)?}))).collect::<Result<Vec<_>>>()?;
                output.emit(
                    json!({"ok":true,"recipients":entries,"file":config.target}),
                    &config
                        .recipients
                        .iter()
                        .map(|(n, k)| format!("{n}\t{k}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                )?;
            }
            RecipientCommand::Add(add) => {
                config.put_recipient(&add.name, &add.public_key)?;
                config.save()?;
                output.emit(json!({"ok":true,"name":add.name,"recipient":add.public_key,"file":config.target}),"Recipient added; run reencrypt to update existing secrets")?;
            }
            RecipientCommand::Remove(remove) => {
                ensure!(
                    !config
                        .secrets
                        .values()
                        .any(|s| s.recipients.contains(&remove.name)),
                    "recipient is referenced; reencrypt with --recipient selecting remaining recipients first"
                );
                let removed = config.target_doc()["recipients"]
                    .as_table_like_mut()
                    .and_then(|t| t.remove(&remove.name));
                ensure!(removed.is_some(), "recipient is not defined in active file");
                config.save()?;
                output.emit(
                    json!({"ok":true,"name":remove.name,"file":config.target}),
                    "Recipient removed (an inherited definition may now be visible)",
                )?;
            }
        },
    }
    Ok(())
}

fn active_names(config: &Config) -> Vec<String> {
    config
        .secrets
        .keys()
        .filter(|name| config.origins[*name] == config.target)
        .cloned()
        .collect()
}

fn secret_from_env(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::ffi::OsStringExt;
    ensure!(
        envelope::valid_name(name),
        "invalid environment variable name"
    );
    let value = std::env::var_os(name)
        .with_context(|| format!("environment variable {name} is not set"))?;
    let value = Zeroizing::new(value.into_vec());
    ensure!(value.len() <= envelope::MAX_SECRET, "secret exceeds 64 KiB");
    Ok(value)
}

fn reset_targets(config: &Config, selected: Option<&str>) -> Result<Vec<String>> {
    if let Some(name) = selected {
        ensure!(
            config.origins.get(name) == Some(&config.target),
            "secret is not defined in active file; use --secrets or --global"
        );
        Ok(vec![name.into()])
    } else {
        Ok(active_names(config))
    }
}

fn reset_values(
    config: &mut Config,
    targets: &[String],
    names: &[String],
    public: &[String],
    mut input: impl FnMut(&str) -> Result<Zeroizing<Vec<u8>>>,
    mut wrap: impl FnMut(&str, &[u8]) -> Result<String>,
) -> Result<()> {
    // Collect only ciphertext until every prompt/encryption succeeds. A failed
    // prompt, cancellation, or conflict leaves the original file intact.
    let mut replacements = Vec::new();
    for name in targets {
        let clear = input(name)?;
        let value = envelope::encrypt(name, &clear, public, &mut wrap)?;
        replacements.push((
            name.clone(),
            Secret {
                recipients: names.to_vec(),
                value,
            },
        ));
    }
    for (name, secret) in replacements {
        config.put_secret(&name, &secret);
    }
    config.save()
}

fn select_identity(
    state: &State,
    envelope: &envelope::Envelope,
    selected: Option<&str>,
) -> Result<String> {
    state.keys.iter().filter(|(key, record)| record.secrets && record.mode == Mode::Prompt
        && selected.is_none_or(|s| s == key.as_str() || record.alias.as_deref() == Some(s))
        && record.fingerprint.as_ref().is_some_and(|f| envelope.wrapped.contains_key(f)))
        .min_by_key(|(_, record)| record.retired)
        .map(|(name, _)| name.clone())
        .context("no enrolled local prompt key matches this secret; check the secrets file for other recipients, or select --identity")
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    fn public(seed: u8) -> String {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let point = p256::SecretKey::from_slice(&[seed; 32])
            .unwrap()
            .public_key();
        envelope::recipient(point.to_encoded_point(false).as_bytes()).unwrap()
    }
    fn seed(global: &std::path::Path, file: &std::path::Path, names: &[&str]) {
        let mut config = Config::load(global, file.parent().unwrap(), Some(file), false).unwrap();
        config.put_recipient("old", &public(1)).unwrap();
        for name in names {
            let value = envelope::encrypt(name, b"old value", &[public(1)], |_, key| {
                Ok(B64.encode(key))
            })
            .unwrap();
            config.put_secret(
                name,
                &Secret {
                    recipients: vec!["old".into()],
                    value,
                },
            );
        }
        config.save().unwrap();
    }

    #[test]
    fn reset_is_atomic_on_cancel_and_encryption_failure_and_scoped_to_selected_file() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global.toml");
        let project = dir.path().join("seccy.toml");
        seed(&global, &global, &["GLOBAL"]);
        seed(&global, &project, &["FIRST", "SECOND"]);
        let before = std::fs::read(&project).unwrap();
        let global_before = std::fs::read(&global).unwrap();
        let selected = vec!["new".into()];
        let recipients = vec![public(2)];
        for fail_input in [true, false] {
            let mut config = Config::load(&global, dir.path(), Some(&project), false).unwrap();
            config.put_recipient("new", &public(2)).unwrap();
            let mut count = 0;
            let mut wraps = 0;
            let targets = active_names(&config);
            assert!(
                reset_values(
                    &mut config,
                    &targets,
                    &selected,
                    &recipients,
                    |_| {
                        count += 1;
                        ensure!(!fail_input || count != 2, "cancelled");
                        Ok(Zeroizing::new(b"new value".to_vec()))
                    },
                    |_, key| {
                        wraps += 1;
                        ensure!(fail_input || wraps != 2, "encryption failed");
                        Ok(B64.encode(key))
                    }
                )
                .is_err()
            );
            assert_eq!(std::fs::read(&project).unwrap(), before);
            assert_eq!(std::fs::read(&global).unwrap(), global_before);
        }
        let mut config = Config::load(&global, dir.path(), None, false).unwrap();
        config.put_recipient("new", &public(2)).unwrap();
        let mut prompted = Vec::new();
        let targets = active_names(&config);
        reset_values(
            &mut config,
            &targets,
            &selected,
            &recipients,
            |name| {
                prompted.push(name.to_string());
                Ok(Zeroizing::new(name.as_bytes().to_vec()))
            },
            |_, key| Ok(B64.encode(key)),
        )
        .unwrap();
        assert_eq!(prompted, ["FIRST", "SECOND"]);
        assert_eq!(std::fs::read(&global).unwrap(), global_before);
        let updated = Config::load(&global, dir.path(), Some(&project), false).unwrap();
        for (name, secret) in &updated.secrets {
            assert_eq!(secret.recipients, selected);
            let parsed = envelope::Envelope::parse(&secret.value, name).unwrap();
            let key = B64.decode(parsed.wrapped.values().next().unwrap()).unwrap();
            assert_eq!(&*parsed.decrypt(&key).unwrap(), name.as_bytes());
        }
        let project_after = std::fs::read(&project).unwrap();
        let mut config = Config::load(&global, dir.path(), None, true).unwrap();
        config.put_recipient("new", &public(2)).unwrap();
        let targets = active_names(&config);
        reset_values(
            &mut config,
            &targets,
            &selected,
            &recipients,
            |name| {
                assert_eq!(name, "GLOBAL");
                Ok(Zeroizing::new(b"global replacement".to_vec()))
            },
            |_, key| Ok(B64.encode(key)),
        )
        .unwrap();
        assert_eq!(std::fs::read(&project).unwrap(), project_after);
    }

    #[test]
    fn reset_one_secret_keeps_other_and_inherited_values() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global.toml");
        let project = dir.path().join("seccy.toml");
        seed(&global, &global, &["INHERITED"]);
        seed(&global, &project, &["FIRST", "SECOND"]);
        let mut config = Config::load(&global, dir.path(), None, false).unwrap();
        let second = config.secrets["SECOND"].value.clone();
        assert!(reset_targets(&config, Some("MISSING")).is_err());
        assert!(reset_targets(&config, Some("INHERITED")).is_err());
        let targets = reset_targets(&config, Some("FIRST")).unwrap();
        reset_values(
            &mut config,
            &targets,
            &["old".into()],
            &[public(1)],
            |name| {
                assert_eq!(name, "FIRST");
                Ok(Zeroizing::new(b"replacement".to_vec()))
            },
            |_, key| Ok(B64.encode(key)),
        )
        .unwrap();
        let updated = Config::load(&global, dir.path(), None, false).unwrap();
        assert_eq!(updated.secrets["SECOND"].value, second);
        assert_eq!(updated.origins["INHERITED"], global);
    }

    #[test]
    fn retained_generation_selected_by_ciphertext_not_reused_alias() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("seccy.toml");
        seed(&file, &file, &["TOKEN"]);
        let config = Config::load(&file, dir.path(), Some(&file), false).unwrap();
        let parsed = envelope::Envelope::parse(&config.secrets["TOKEN"].value, "TOKEN").unwrap();
        let mut state = State::default();
        state
            .overlay(
                &seccy_core::Config::parse("[keys.auth]\nmode='prompt'").unwrap(),
                &file,
            )
            .unwrap();
        let record = state.keys.get_mut("auth").unwrap();
        record.secrets = true;
        record.fingerprint = Some(envelope::fingerprint(&public(1)).unwrap());
        let mut retired = record.clone();
        retired.retired = true;
        retired.alias = Some("auth".into());
        state.keys.get_mut("auth").unwrap().fingerprint =
            Some(envelope::fingerprint(&public(2)).unwrap());
        state.keys.insert("old-generation".into(), retired);
        // The picker offers active keys, while old ciphertext still resolves below.
        assert_eq!(enrollment_candidates(&state), vec!["auth"]);
        let mut notify = state.keys["auth"].clone();
        notify.mode = Mode::Notify;
        state.keys.insert("notification-only".into(), notify);
        assert_eq!(enrollment_candidates(&state), vec!["auth"]);
        assert_eq!(
            select_identity(&state, &parsed, None).unwrap(),
            "old-generation"
        );
        assert_eq!(
            select_identity(&state, &parsed, Some("auth")).unwrap(),
            "old-generation"
        );
        assert!(select_identity(&state, &parsed, Some("unrelated")).is_err());
    }
}
