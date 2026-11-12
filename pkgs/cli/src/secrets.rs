//! Local secrets protocol. Payloads and responses must never enter tracing.
use crate::platform;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use seccy_core::agent;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    path::PathBuf,
    sync::Mutex,
    time::Duration,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: String,
    key: String,
    value: Option<String>,
}

pub fn read_stdin(limit: usize) -> Result<Vec<u8>> {
    let mut input = Vec::new();
    std::io::stdin()
        .take((limit + 1) as u64)
        .read_to_end(&mut input)?;
    ensure!(input.len() <= limit, "stdin exceeds size limit");
    Ok(input)
}

pub fn decrypt(args: super::SecretArgs, output: &crate::Output) -> Result<()> {
    let input =
        String::from_utf8(read_stdin(128 * 1024 + 2)?).context("ciphertext must be UTF-8")?;
    let response = request(
        args.socket,
        "decrypt",
        &args.name,
        Some(input.trim_end_matches(['\r', '\n']).into()),
    )?;
    let bytes = STANDARD.decode(
        response["value_base64"]
            .as_str()
            .context("invalid agent response")?,
    )?;
    if output.structured() {
        // Base64 preserves arbitrary bytes, including non-UTF-8 and trailing newlines.
        super::emit(
            output,
            json!({"ok": true, "value_base64": STANDARD.encode(bytes)}),
            "",
        )?;
    } else {
        std::io::stdout().write_all(&bytes)?;
    }
    Ok(())
}

pub fn request(
    socket: Option<PathBuf>,
    operation: &str,
    key: &str,
    value: Option<String>,
) -> Result<Value> {
    let socket = match socket {
        Some(socket) => socket,
        None => seccy_core::storage::Paths::from_env()?
            .runtime
            .join("secrets.sock"),
    };
    let metadata = std::fs::symlink_metadata(&socket)
        .context("seccy agent unavailable; start `seccy agent`")?;
    use std::os::unix::fs::FileTypeExt;
    ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "secrets socket must be an owned private socket"
    );
    let mut stream = UnixStream::connect(&socket)
        .context("connect to seccy agent; start or restart the agent")?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(120)))?;
    platform::caller(&stream)?;
    agent::write_frame(
        &mut stream,
        &serde_json::to_vec(&Request {
            operation: operation.into(),
            key: key.into(),
            value,
        })?,
    )?;
    let frame = agent::read_frame(&mut stream)?.context("agent closed connection")?;
    let response: Value = serde_json::from_slice(&frame).context("invalid agent response")?;
    ensure!(
        response["ok"] == true,
        "{}",
        response["error"]
            .as_str()
            .unwrap_or("secrets operation failed")
    );
    Ok(response)
}

pub fn serve(
    mut stream: UnixStream,
    keys: &super::inventory::Cached,
    operations: &Mutex<()>,
) -> Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(120)))?;
    let connected = platform::caller(&stream)?;
    let result = (|| -> Result<Value> {
        let frame = agent::read_frame(&mut stream)?.context("empty secrets request")?;
        // Do not expose serde errors: they can contain client-supplied values.
        let request: Request = serde_json::from_slice(&frame)
            .map_err(|_| anyhow::anyhow!("invalid secrets request"))?;
        let _guard = operations
            .lock()
            .map_err(|_| anyhow::anyhow!("key operation lock poisoned"))?;
        let (_state_lock, keys) = keys.keys()?;
        let identity = keys
            .iter()
            .find(|key| key.name == request.key)
            .context("key is not configured and provisioned in the agent")?;
        match request.operation.as_str() {
            #[cfg(target_os = "macos")]
            "decrypt-managed" => {
                use seccy_core::{Mode, envelope::Envelope, state::State, storage::Paths};
                use zeroize::Zeroizing;
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Managed {
                    name: String,
                    value: String,
                }
                let value = request.value.context("missing ciphertext")?;
                let managed: Managed = serde_json::from_str(&value)
                    .map_err(|_| anyhow::anyhow!("invalid managed secrets request"))?;
                let state = State::load(&Paths::from_env()?)?;
                ensure!(
                    state.keys.get(&identity.name).is_some_and(|r| r.secrets)
                        && identity.mode == Mode::Prompt,
                    "key is not enrolled for managed secrets with prompt authorization"
                );
                let envelope = Envelope::parse(&managed.value, &managed.name)?;
                let wrapped = envelope
                    .wrapped
                    .get(&identity.fingerprint)
                    .context("key is not a recipient")?;
                let caller = platform::caller(&stream)?;
                ensure!(caller.pid == connected.pid, "socket peer changed");
                if let (Some(before), Some(now)) = (&connected.process, &caller.process) {
                    ensure!(
                        before.start_time_unix_seconds == now.start_time_unix_seconds
                            && before.start_time_microseconds == now.start_time_microseconds,
                        "socket peer process changed"
                    );
                }
                let file_key = Zeroizing::new(seccy_macos::SecureEnclave.decrypt_secret(
                    identity,
                    wrapped,
                    &caller,
                    Some(&managed.name),
                )?);
                let plaintext = envelope.decrypt(&file_key)?;
                Ok(json!({"ok": true, "value_base64": STANDARD.encode(&*plaintext)}))
            }
            #[cfg(target_os = "macos")]
            "decrypt-managed-batch" => {
                use seccy_core::{Mode, envelope::Envelope, state::State, storage::Paths};
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Entry {
                    key: String,
                    name: String,
                    value: String,
                }
                let entries: Vec<Entry> =
                    serde_json::from_str(&request.value.context("missing ciphertext")?)
                        .map_err(|_| anyhow::anyhow!("invalid managed secrets batch"))?;
                ensure!(!entries.is_empty(), "empty managed secrets batch");
                let state = State::load(&Paths::from_env()?)?;
                let mut names = std::collections::BTreeSet::new();
                let mut prepared = Vec::new();
                for entry in &entries {
                    ensure!(names.insert(&entry.name), "duplicate secret name");
                    let identity = keys
                        .iter()
                        .find(|key| key.name == entry.key)
                        .context("key is not configured and provisioned in the agent")?;
                    ensure!(
                        state.keys.get(&identity.name).is_some_and(|r| r.secrets)
                            && identity.mode == Mode::Prompt,
                        "key is not enrolled for managed secrets with prompt authorization"
                    );
                    let envelope = Envelope::parse(&entry.value, &entry.name)?;
                    ensure!(
                        envelope.wrapped.contains_key(&identity.fingerprint),
                        "key is not a recipient"
                    );
                    prepared.push((identity, envelope));
                }
                let caller = platform::caller(&stream)?;
                ensure!(caller.pid == connected.pid, "socket peer changed");
                if let (Some(before), Some(now)) = (&connected.process, &caller.process) {
                    ensure!(
                        before.start_time_unix_seconds == now.start_time_unix_seconds
                            && before.start_time_microseconds == now.start_time_microseconds,
                        "socket peer process changed"
                    );
                }
                let items: Vec<_> = prepared
                    .iter()
                    .zip(&entries)
                    .map(|((identity, envelope), entry)| {
                        (
                            *identity,
                            envelope.wrapped[&identity.fingerprint].as_str(),
                            entry.name.as_str(),
                        )
                    })
                    .collect();
                let file_keys = seccy_macos::SecureEnclave.decrypt_secrets(&items, &caller)?;
                let mut values = zeroize::Zeroizing::new(Vec::<String>::new());
                for ((_, envelope), key) in prepared.iter().zip(file_keys) {
                    values.push(STANDARD.encode(&*envelope.decrypt(&key)?));
                }
                Ok(json!({"ok": true, "values_base64": &*values}))
            }
            "check" => {
                ensure!(request.value.is_none(), "check does not accept a payload");
                platform::Store.crypto_check(identity)?;
                Ok(
                    json!({"ok": true, "key": identity.name, "fingerprint": identity.fingerprint, "mode": identity.mode}),
                )
            }
            "decrypt" => {
                let value = request.value.context("missing ciphertext")?;
                let caller = platform::caller(&stream)?;
                ensure!(caller.pid == connected.pid, "socket peer changed");
                if let (Some(before), Some(now)) = (&connected.process, &caller.process) {
                    ensure!(
                        before.start_time_unix_seconds == now.start_time_unix_seconds
                            && before.start_time_microseconds == now.start_time_microseconds,
                        "socket peer process changed"
                    );
                }
                let plaintext = platform::Store.decrypt(identity, &value, &caller)?;
                Ok(json!({"ok": true, "value_base64": STANDARD.encode(plaintext)}))
            }
            _ => anyhow::bail!("unsupported secrets operation"),
        }
    })();
    let response = match result {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(event = "secrets_request_failed");
            json!({"ok": false, "error": format!("{error:#}")})
        }
    };
    agent::write_frame(&mut stream, &serde_json::to_vec(&response)?)
}
