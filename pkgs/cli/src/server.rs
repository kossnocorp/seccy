use crate::platform;
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use seccy_core::agent;
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

pub fn private_dir(path: &Path) -> Result<()> {
    match fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
    {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "{} must be an owned, non-symlink directory with permissions 0700",
        path.display()
    );
    Ok(())
}

pub fn lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        file.metadata()?.uid() == unsafe { libc::geteuid() },
        "lock is owned by another user"
    );
    file.try_lock_exclusive()
        .context("another seccy process holds this lock")?;
    Ok(file)
}

struct SocketGuard(PathBuf);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn run(socket: Option<PathBuf>, output: &crate::Output) -> Result<()> {
    let socket = match socket {
        Some(path) => std::path::absolute(path)?,
        None => seccy_core::storage::Paths::from_env()?
            .runtime
            .join("agent.sock"),
    };
    private_dir(
        socket
            .parent()
            .context("socket must have a parent directory")?,
    )?;
    let _lock = lock(&socket.with_extension("lock"))?;
    let secrets_socket = socket.with_file_name("secrets.sock");
    ensure!(
        socket != secrets_socket,
        "SSH socket cannot be named secrets.sock"
    );
    let _secrets_lock = lock(&secrets_socket.with_extension("lock"))?;
    let listener = bind(&socket)?;
    let _socket_guard = SocketGuard(socket.clone());
    let secrets_listener = bind(&secrets_socket)?;
    let _secrets_guard = SocketGuard(secrets_socket.clone());
    let keys = Arc::new(super::inventory::Cached::default());
    let key_count = keys.keys(false)?.1.len();
    let stopped = Arc::new(AtomicBool::new(false));
    let signal = stopped.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
    let active = Arc::new(AtomicUsize::new(0));
    let signing = Arc::new(Mutex::new(()));
    let (output_errors, errors) = std::sync::mpsc::channel();
    tracing::info!(event = "agent_ready", socket = %socket.display(), secrets_socket = %secrets_socket.display(), key_count);
    super::emit(
        output,
        json!({"ok": true, "event": "ready", "socket": socket, "secrets_socket": secrets_socket}),
        &format!(
            "SSH_AUTH_SOCK={}\nSecrets socket: {}",
            socket.display(),
            secrets_socket.display()
        ),
    )?;
    while !stopped.load(Ordering::Relaxed) {
        for (listener, secrets) in [(&listener, false), (&secrets_listener, true)] {
            match listener.accept() {
                Ok((stream, _)) => {
                    if active.load(Ordering::Relaxed) >= 16 {
                        tracing::warn!(event = "connection_limit_reached");
                        continue;
                    }
                    active.fetch_add(1, Ordering::Relaxed);
                    let active = active.clone();
                    let keys = keys.clone();
                    let signing = signing.clone();
                    let output = output.clone();
                    let stopped = stopped.clone();
                    let output_errors = output_errors.clone();
                    std::thread::spawn(move || {
                        let result = if secrets {
                            super::secrets::serve(stream, &keys, &signing)
                        } else {
                            serve(stream, &keys, &signing, &output)
                        };
                        if let Err(error) = result {
                            let result = if error.is::<crate::output::QueryError>() {
                                Err(error)
                            } else {
                                event_error(&output, &error)
                            };
                            if let Err(error) = result {
                                let _ = output_errors.send(error);
                                stopped.store(true, Ordering::Relaxed);
                            }
                        }
                        active.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => return Err(e.into()),
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    tracing::info!(event = "agent_stopped");
    if let Ok(error) = errors.try_recv() {
        return Err(error);
    }
    Ok(())
}

fn bind(socket: &Path) -> Result<UnixListener> {
    if let Ok(meta) = fs::symlink_metadata(socket) {
        ensure!(
            meta.file_type().is_socket() && meta.uid() == unsafe { libc::geteuid() },
            "refusing to replace non-owned socket path"
        );
        match UnixStream::connect(socket) {
            Ok(_) => anyhow::bail!("an agent is already listening on {}", socket.display()),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => fs::remove_file(socket)?,
            Err(e) => return Err(e).context("check existing socket"),
        }
    }
    let listener = UnixListener::bind(socket).context("bind agent socket")?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn event_error(output: &crate::Output, error: &anyhow::Error) -> Result<()> {
    tracing::error!(event = "request_error", error = %format!("{error:#}"));
    if output.structured() {
        output.emit(
            json!({"ok": false, "event": "request_error", "error": format!("{error:#}")}),
            "",
        )?;
    } else {
        eprintln!("agent: {error:#}");
    }
    Ok(())
}

fn serve(
    mut stream: UnixStream,
    keys: &super::inventory::Cached,
    signing: &Mutex<()>,
    output: &crate::Output,
) -> Result<()> {
    // Darwin inherits O_NONBLOCK from the listener on accepted sockets.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(120)))?;
    let connected = platform::caller(&stream)?;
    tracing::info!(event = "client_connected", caller_json = %serde_json::to_string(&connected)?);
    while let Some(request) = agent::read_frame(&mut stream)? {
        // Serialize biometric prompts and notification delivery across clients.
        let _guard = if request.first() == Some(&13) {
            Some(
                signing
                    .lock()
                    .map_err(|_| anyhow::anyhow!("signing lock poisoned"))?,
            )
        } else {
            None
        };
        let caller = platform::caller(&stream)?;
        ensure!(caller.pid == connected.pid, "socket peer changed");
        if let (Some(before), Some(now)) = (&connected.process, &caller.process) {
            ensure!(
                (
                    before.start_time_unix_seconds,
                    before.start_time_microseconds
                ) == (now.start_time_unix_seconds, now.start_time_microseconds),
                "socket peer PID was reused"
            );
        }
        let (_state_lock, current_keys) = keys.keys(false)?;
        let response = match agent::respond(&platform::Store, &current_keys, &caller, &request) {
            Ok(response) => response,
            Err(error) => {
                event_error(output, &error)?;
                vec![agent::FAILURE]
            }
        };
        agent::write_frame(&mut stream, &response)?;
        tracing::debug!(
            event = "agent_response",
            request_type = request[0],
            response_type = response[0],
            peer_pid = caller.pid
        );
        if response.first() == Some(&14) {
            // A successful response means the request was fully validated.
            // Its key blob starts after the message type and string length.
            let key = current_keys
                .iter()
                .find(|key| request.get(5..5 + key.blob.len()) == Some(key.blob.as_slice()))
                .context("signed key missing from advertised identities")?;
            tracing::info!(event = "signature_delivered", key = %key.name, fingerprint = %key.fingerprint, peer_pid = caller.pid);
            if output.structured() {
                output.emit(json!({"ok": true, "event": "signed", "key": key.name, "fingerprint": key.fingerprint, "caller": caller}), "")?;
            } else {
                eprintln!(
                    "Key {} used by {} (PID {})",
                    key.name, caller.executable, caller.pid
                );
            }
        }
    }
    tracing::info!(event = "client_disconnected", peer_pid = connected.pid);
    Ok(())
}
