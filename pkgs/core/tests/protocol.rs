use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use seccy_core::{Caller, Config, Identity, KeyStore, Mode, agent};
use std::sync::atomic::{AtomicUsize, Ordering};

// Keep callsite registration from racing the scoped subscribers in the logging
// test. The OpenSSH test also invokes these callsites from its agent thread.
static AGENT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Store {
    key: SigningKey,
    calls: AtomicUsize,
}
impl Store {
    fn new() -> Self {
        Self {
            key: SigningKey::from_bytes((&[1u8; 32]).into()).unwrap(),
            calls: AtomicUsize::new(0),
        }
    }
}
impl KeyStore for Store {
    fn provision(&self, _: &str, _: Mode) -> anyhow::Result<(Identity, bool)> {
        unreachable!()
    }
    fn identity(&self, name: &str, mode: Mode) -> anyhow::Result<Option<Identity>> {
        Identity::new(
            name,
            mode,
            self.key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .map(Some)
    }
    fn sign(
        &self,
        _: &Identity,
        message: &[u8],
        _: &Caller,
        _: &seccy_core::payload::Payload,
    ) -> anyhow::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let signature: Signature = self.key.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
fn caller() -> Caller {
    Caller {
        pid: 1,
        executable: "test".into(),
        ..Caller::default()
    }
}

#[test]
fn invalid_requests_never_reach_signer() {
    let _guard = AGENT_TEST_LOCK.lock().unwrap();
    let store = Store::new();
    let keys = vec![store.identity("test", Mode::Notify).unwrap().unwrap()];
    let mut valid = vec![13];
    agent::string(&mut valid, &keys[0].blob);
    agent::string(&mut valid, b"message");
    valid.extend_from_slice(&0u32.to_be_bytes());
    for end in 0..valid.len() {
        assert!(agent::respond(&store, &keys, &caller(), &valid[..end]).is_err());
    }
    let mut flags = valid.clone();
    *flags.last_mut().unwrap() = 1;
    assert!(agent::respond(&store, &keys, &caller(), &flags).is_err());
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(agent::respond(&store, &keys, &caller(), &trailing).is_err());
    assert!(agent::respond(&store, &[], &caller(), &valid).is_err());
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        agent::respond(&store, &keys, &caller(), &valid).unwrap()[0],
        14
    );
}

#[test]
fn framing_rejects_oversized_and_truncated_input() {
    for bytes in [
        &[0, 0][..],
        &[0, 0, 0, 0],
        &[0, 0, 0, 2, 11],
        &[255, 255, 255, 255],
    ] {
        assert!(agent::read_frame(&mut &bytes[..]).is_err());
    }
    assert!(agent::read_frame(&mut &[][..]).unwrap().is_none());
    assert_eq!(
        agent::read_frame(&mut &[0, 0, 0, 1, 11][..])
            .unwrap()
            .unwrap(),
        [11]
    );
}

#[test]
fn config_is_strict() {
    assert!(Config::parse(include_str!("../../../config.example.toml")).is_ok());
    for text in [
        "[keys.bad]\nmode='silent'",
        "[keys.bad]\nmode='notify'\nextra=true",
        "[keys.'../bad']\nmode='notify'",
    ] {
        assert!(Config::parse(text).is_err(), "{text}");
    }
}

#[test]
fn debug_logging_contains_exact_payload_but_info_does_not() {
    let _guard = AGENT_TEST_LOCK.lock().unwrap();
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    for level in [tracing::Level::INFO, tracing::Level::DEBUG] {
        let capture = Capture(Arc::new(Mutex::new(Vec::new())));
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_ansi(false)
            .with_max_level(level)
            .with_writer(move || writer.clone())
            .finish();
        let store = Store::new();
        let keys = vec![store.identity("test", Mode::Notify).unwrap().unwrap()];
        let payload = b"SSHSIG\0\xff\ninspect these exact bytes";
        let mut request = vec![13];
        agent::string(&mut request, &keys[0].blob);
        agent::string(&mut request, payload);
        request.extend_from_slice(&0u32.to_be_bytes());
        tracing::subscriber::with_default(subscriber, || {
            agent::respond(&store, &keys, &caller(), &request).unwrap();
        });
        let bytes = capture.0.lock().unwrap();
        let events: Vec<serde_json::Value> = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let requested = events
            .iter()
            .find(|e| e["fields"]["event"] == "sign_requested")
            .unwrap();
        assert_eq!(requested["fields"]["payload_length"], payload.len());
        let caller: serde_json::Value =
            serde_json::from_str(requested["fields"]["caller_json"].as_str().unwrap()).unwrap();
        assert_eq!(caller["executable"], "test");
        let dump = events
            .iter()
            .find(|e| e["fields"]["event"] == "sign_payload");
        if level == tracing::Level::DEBUG {
            let encoded = dump.unwrap()["fields"]["payload"].as_str().unwrap();
            assert_eq!(STANDARD.decode(encoded).unwrap(), payload);
        } else {
            assert!(dump.is_none());
        }
    }
}

/// Exercise the real OpenSSH/Git clients against our wire protocol, using a
/// software test key only. Production has no software-key implementation.
#[cfg(unix)]
#[test]
fn git_signed_commit_and_openssh_identity_listing() {
    let _guard = AGENT_TEST_LOCK.lock().unwrap();
    use std::{
        os::unix::net::UnixListener,
        process::Command,
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };
    // Short socket path avoids sockaddr_un limits on macOS.
    let dir = tempfile::Builder::new()
        .prefix("sc-")
        .tempdir_in(std::env::temp_dir())
        .unwrap();
    let socket = dir.path().join("a");
    let store = Store::new();
    let identity = store.identity("test", Mode::Notify).unwrap().unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let keys = vec![identity.clone()];
    let worker = std::thread::spawn(move || {
        while !stopping.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    while let Some(request) = agent::read_frame(&mut stream).unwrap() {
                        let response =
                            agent::respond(&store, &keys, &caller(), &request).unwrap_or(vec![5]);
                        agent::write_frame(&mut stream, &response).unwrap();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("{e}"),
            }
        }
        store.calls.load(Ordering::SeqCst)
    });
    let run = |program: &str, args: &[&str]| {
        let output = Command::new(program)
            .args(args)
            .current_dir(dir.path())
            .env("SSH_AUTH_SOCK", &socket)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{program} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    let listed = run("ssh-add", &["-L"]);
    assert_eq!(
        String::from_utf8(listed.stdout).unwrap().trim(),
        identity.public_key
    );
    std::fs::write(dir.path().join("key.pub"), &identity.public_key).unwrap();
    std::fs::write(
        dir.path().join("allowed_signers"),
        format!("test@example.com {}\n", identity.public_key),
    )
    .unwrap();
    run("git", &["init", "--quiet"]);
    for (key, value) in [
        ("user.name", "Test"),
        ("user.email", "test@example.com"),
        ("gpg.format", "ssh"),
        ("user.signingkey", "key.pub"),
        ("gpg.ssh.allowedSignersFile", "allowed_signers"),
    ] {
        run("git", &["config", key, value]);
    }
    run(
        "git",
        &[
            "-c",
            "commit.gpgsign=true",
            "commit",
            "--allow-empty",
            "-m",
            "Signed via seccy protocol",
        ],
    );
    run("git", &["verify-commit", "HEAD"]);
    stop.store(true, Ordering::SeqCst);
    assert_eq!(worker.join().unwrap(), 1);
}
