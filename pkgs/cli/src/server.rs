use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use seccy_core::{Config, KeyStore, agent};
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

pub fn run(config: Config, socket: Option<PathBuf>, json_mode: bool) -> Result<()> {
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
    if let Ok(meta) = fs::symlink_metadata(&socket) {
        ensure!(
            meta.file_type().is_socket() && meta.uid() == unsafe { libc::geteuid() },
            "refusing to replace non-owned socket path"
        );
        match UnixStream::connect(&socket) {
            Ok(_) => anyhow::bail!("an agent is already listening on {}", socket.display()),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                fs::remove_file(&socket)?
            }
            Err(e) => return Err(e).context("check existing socket"),
        }
    }
    let keys = Arc::new(
        config
            .keys
            .iter()
            .map(|(name, key)| seccy_macos::SecureEnclave.identity(name, key.mode))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .map(|identity| identity.with_user(&config.user))
            .collect::<Vec<_>>(),
    );
    let listener = UnixListener::bind(&socket).context("bind agent socket")?;
    let _socket_guard = SocketGuard(socket.clone());
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let signal = stopped.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
    let active = Arc::new(AtomicUsize::new(0));
    let signing = Arc::new(Mutex::new(()));
    super::emit(
        json_mode,
        json!({"ok": true, "event": "ready", "socket": socket}),
        &format!("SSH_AUTH_SOCK={}", socket.display()),
    );
    while !stopped.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                if active.load(Ordering::Relaxed) >= 16 {
                    continue;
                }
                active.fetch_add(1, Ordering::Relaxed);
                let active = active.clone();
                let keys = keys.clone();
                let signing = signing.clone();
                std::thread::spawn(move || {
                    if let Err(error) = serve(stream, &keys, &signing, json_mode) {
                        event_error(json_mode, &error);
                    }
                    active.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn event_error(json_mode: bool, error: &anyhow::Error) {
    if json_mode {
        println!(
            "{}",
            json!({"ok": false, "event": "request_error", "error": format!("{error:#}")})
        );
    } else {
        eprintln!("agent: {error:#}");
    }
}

fn serve(
    mut stream: UnixStream,
    keys: &[seccy_core::Identity],
    signing: &Mutex<()>,
    json_mode: bool,
) -> Result<()> {
    // Darwin inherits O_NONBLOCK from the listener on accepted sockets.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(120)))?;
    let caller = seccy_macos::caller(&stream)?;
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
        let response = match agent::respond(&seccy_macos::SecureEnclave, keys, &caller, &request) {
            Ok(response) => response,
            Err(error) => {
                event_error(json_mode, &error);
                vec![agent::FAILURE]
            }
        };
        agent::write_frame(&mut stream, &response)?;
        if response.first() == Some(&14) {
            // A successful response means the request was fully validated.
            // Its key blob starts after the message type and string length.
            let key = keys
                .iter()
                .find(|key| request.get(5..5 + key.blob.len()) == Some(key.blob.as_slice()))
                .context("signed key missing from advertised identities")?;
            if json_mode {
                println!(
                    "{}",
                    json!({"ok": true, "event": "signed", "key": key.name, "fingerprint": key.fingerprint, "caller": caller})
                );
            } else {
                eprintln!(
                    "Key {} used by {} (PID {})",
                    key.name, caller.executable, caller.pid
                );
            }
        }
    }
    Ok(())
}
