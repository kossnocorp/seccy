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
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{IsTerminal, Read, Write},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
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
fn decrypt(name: &str, secret: &Secret, selected: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
    let paths = Paths::from_env()?;
    let _lock = crate::inventory::read_lock(&paths)?;
    let state = State::load(&paths)?;
    let envelope = envelope::Envelope::parse(&secret.value, name)?;
    let identity = state.keys.iter().find(|(key, record)| record.secrets && record.mode == Mode::Prompt
        && selected.is_none_or(|s| s == key.as_str())
        && record.fingerprint.as_ref().is_some_and(|f| envelope.wrapped.contains_key(f)))
        .map(|(name,_)| name.clone()).context("no enrolled local prompt key matches this secret; enroll a matching key or select --identity")?;
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
fn decrypt_batch(
    names: &[String],
    config: &Config,
    selected: Option<&str>,
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
        let identity = state.keys.iter().find(|(key, record)| record.secrets && record.mode == Mode::Prompt
            && selected.is_none_or(|s| s == key.as_str())
            && record.fingerprint.as_ref().is_some_and(|f| envelope.wrapped.contains_key(f)))
            .map(|(name,_)| name).context("no enrolled local prompt key matches this secret; enroll a matching key or select --identity")?;
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
pub fn run(mut args: SecretsArgs, output: &Output) -> Result<()> {
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
    let paths = Paths::from_env()?;
    let global = paths.config.with_file_name("secrets.toml");
    let cwd = std::env::current_dir()?;
    let mutation = matches!(
        args.command,
        SecretsCommand::Set(_)
            | SecretsCommand::Enroll(_)
            | SecretsCommand::Reencrypt(_)
            | SecretsCommand::Remove(_)
            | SecretsCommand::Recipients(RecipientArgs {
                command: RecipientCommand::Add(_) | RecipientCommand::Remove(_)
            })
    );
    ensure!(
        !(args.global && args.file.is_some()),
        "--global and --secrets are mutually exclusive"
    );
    if mutation && !args.global && args.file.is_none() {
        let mut detected = crate::secret_config::detected_files(&global, &cwd)?;
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
        }
    }
    let mut config = Config::load(&global, &cwd, args.file.as_deref(), args.global)?;
    let _file_lock = if mutation {
        let parent = config.target.parent().context("invalid secrets path")?;
        if config.target == global {
            crate::secret_config::config_dir(parent)?;
        }
        let lock = crate::secret_config::writer_lock(&paths.state, &config.target)?;
        // Reload after locking so concurrent Seccy writers cannot overwrite each other.
        config = Config::load(&global, &cwd, args.file.as_deref(), args.global)?;
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
            let value = decrypt(&get.name, secret, args.identity.as_deref())?;
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
            let distinct: BTreeSet<_> = names.iter().collect();
            ensure!(distinct.len() == names.len(), "duplicate secret name");
            for name in &names {
                ensure!(config.secrets.contains_key(name), "unknown secret {name}");
            }
            let mut child = Command::new(&command[0]);
            child.args(&command[1..]);
            let values = decrypt_batch(&names, &config, args.identity.as_deref())?;
            for (name, bytes) in names.iter().zip(values) {
                ensure!(
                    !bytes.contains(&0),
                    "secret {name} contains NUL and cannot be an environment value"
                );
                use std::os::unix::ffi::OsStrExt;
                child.env(name, std::ffi::OsStr::from_bytes(&bytes));
            }
            // exec preserves child exit codes/signals and doesn't expose secrets in argv.
            return Err(child.exec()).context("execute command with secrets");
        }
        SecretsCommand::Enroll(enroll) => {
            crate::server::private_dir(&paths.state)?;
            let _lock = crate::server::lock(&paths.state.join("state.lock"))?;
            let mut state = State::load(&paths)?;
            let candidates = state
                .keys
                .iter()
                .filter(|(_, r)| r.mode == Mode::Prompt)
                .map(|(n, _)| n.clone())
                .collect::<Vec<_>>();
            let key = match enroll.key {
                Some(k) => k,
                None => choose(&candidates, "prompt key", output)?,
            };
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
            seccy_macos::SecureEnclave.crypto_check(&identity)?;
            let public = envelope::from_identity(&identity)?;
            let alias = enroll.name.unwrap_or(key.clone());
            config.put_recipient(&alias, &public)?;
            state.keys.get_mut(&key).unwrap().secrets = true;
            // Enrollment is idempotent; a failed config write can be retried safely.
            state.save(&paths)?;
            config.save()?;
            output.emit(json!({"ok":true,"key":key,"name":alias,"recipient":public,"fingerprint":identity.fingerprint,"file":config.target}), &public)?;
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
                let clear = decrypt(name, secret, args.identity.as_deref())?;
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
