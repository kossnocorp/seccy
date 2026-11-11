#![cfg(target_os = "macos")]
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use seccy_core::{Identity, Mode, envelope};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::Path,
    process::{Command, Output, Stdio},
};

fn identity() -> Identity {
    let hex = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    let point = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    Identity::new("test-key", Mode::Prompt, &point).unwrap()
}
fn cmd(dir: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_seccy"));
    c.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("XDG_RUNTIME_DIR", dir.join("run"))
        .env("LOG_LEVEL", "trace")
        .stdin(Stdio::null());
    c
}
fn ok(output: Output) -> Value {
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}
fn initialize(dir: &Path) -> String {
    let public = envelope::from_identity(&identity()).unwrap();
    ok(cmd(dir)
        .args(["s", "recipients", "add", "mac", &public, "--json"])
        .output()
        .unwrap());
    public
}
fn set(dir: &Path, name: &str, bytes: &[u8]) {
    let mut c = cmd(dir)
        .args(["s", "set", name, "--from-stdin", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(bytes).unwrap();
    ok(c.wait_with_output().unwrap());
}
fn mock_agent(
    dir: &Path,
    responses: Vec<Result<Vec<u8>, &'static str>>,
) -> std::thread::JoinHandle<()> {
    let paths = seccy_core::storage::Paths::resolve(Some(dir), |name| match name {
        "XDG_CONFIG_HOME" => Some(dir.join("config")),
        "XDG_STATE_HOME" => Some(dir.join("state")),
        "XDG_RUNTIME_DIR" => Some(dir.join("run")),
        _ => None,
    })
    .unwrap();
    fs::create_dir_all(&paths.state).unwrap();
    fs::set_permissions(&paths.state, fs::Permissions::from_mode(0o700)).unwrap();
    let key = identity();
    let state = seccy_core::state::State {
        keys: [(
            key.name.clone(),
            seccy_core::state::Record {
                secrets: true,
                mode: Mode::Prompt,
                github: None,
                config: paths.config.clone(),
                email: None,
                public_key: Some(key.public_key),
                fingerprint: Some(key.fingerprint),
            },
        )]
        .into(),
    };
    state.save(&paths).unwrap();
    fs::create_dir_all(&paths.runtime).unwrap();
    fs::set_permissions(&paths.runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = paths.runtime.join("secrets.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    // Nonblocking accept gives a failing CLI test a bounded failure instead of a hang.
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        for response in responses {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "CLI never connected to agent"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let request: Value = serde_json::from_slice(
                &seccy_core::agent::read_frame(&mut stream).unwrap().unwrap(),
            )
            .unwrap();
            assert_eq!(request["operation"], "decrypt-managed");
            assert_eq!(request["key"], "test-key");
            let response = match response {
                Ok(bytes) => json!({"ok":true,"value_base64":B64.encode(bytes)}),
                Err(error) => json!({"ok":false,"error":error}),
            };
            seccy_core::agent::write_frame(&mut stream, &serde_json::to_vec(&response).unwrap())
                .unwrap();
        }
        fs::remove_file(socket).unwrap();
    })
}
#[test]
fn public_only_set_list_query_and_binary_get() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let dir = dir.path();
    let public = initialize(dir);
    let bytes = b"do-not-log-this\0\xff\n\n";
    set(dir, "TOKEN", bytes);
    let text = fs::read_to_string(dir.join("seccy.toml")).unwrap();
    assert!(!text.contains("do-not-log-this"));
    assert!(text.contains(&public));
    assert_eq!(
        fs::metadata(dir.join("seccy.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let listing = ok(cmd(dir).args(["s", "list", "--json"]).output().unwrap());
    assert_eq!(listing["secrets"][0]["name"], "TOKEN");
    assert!(listing["secrets"][0].get("value").is_none());
    let query = cmd(dir)
        .args(["s", "list", "--jq-raw", ".secrets[0].name"])
        .output()
        .unwrap();
    assert_eq!(query.stdout, b"TOKEN\n");
    let server = mock_agent(dir, vec![Ok(bytes.to_vec()), Ok(bytes.to_vec())]);
    let raw = cmd(dir).args(["s", "get", "TOKEN"]).output().unwrap();
    assert!(raw.status.success(), "{raw:?}");
    assert_eq!(raw.stdout, bytes);
    let result = ok(cmd(dir)
        .args(["s", "get", "TOKEN", "--json"])
        .output()
        .unwrap());
    assert_eq!(result["value_base64"], B64.encode(bytes));
    server.join().unwrap();
    let logs = fs::read_to_string(dir.join("state/seccy/logs/seccy.jsonl")).unwrap();
    assert!(!logs.contains("do-not-log-this"));
    assert!(!logs.contains(&B64.encode(bytes)));
}
#[test]
fn exec_selection_all_arguments_exit_status_and_auth_failure() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let dir = dir.path();
    initialize(dir);
    set(dir, "FIRST", b"a");
    set(dir, "SECOND", b"b");
    let server = mock_agent(dir, vec![Ok(b"selected".to_vec())]);
    let out = cmd(dir)
        .args([
            "s",
            "exec",
            "FIRST",
            "--",
            "/bin/sh",
            "-c",
            "test \"$FIRST\" = selected && test -z \"${SECOND+x}\"; exit 23",
        ])
        .env_remove("SECOND")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23), "{out:?}");
    server.join().unwrap();
    let server = mock_agent(dir, vec![Ok(b"a".to_vec()), Ok(b"b".to_vec())]);
    let out = cmd(dir)
        .args([
            "s",
            "exec",
            "--",
            "/bin/sh",
            "-c",
            "test \"$FIRST$SECOND\" = ab",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    server.join().unwrap();
    let server = mock_agent(dir, vec![Err("cancelled")]);
    let out = cmd(dir)
        .args([
            "s",
            "exec",
            "FIRST",
            "--",
            "/usr/bin/touch",
            "SHOULD_NOT_EXIST",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!dir.join("SHOULD_NOT_EXIST").exists());
    server.join().unwrap();
}
#[test]
fn reencrypt_failure_is_atomic_and_success_updates_recipients() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let dir = dir.path();
    initialize(dir);
    set(dir, "FIRST", b"a");
    set(dir, "SECOND", b"b");
    let before = fs::read(dir.join("seccy.toml")).unwrap();
    let server = mock_agent(dir, vec![Ok(b"a".to_vec()), Err("cancelled")]);
    let out = cmd(dir)
        .args(["s", "reencrypt", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    server.join().unwrap();
    assert_eq!(fs::read(dir.join("seccy.toml")).unwrap(), before);
    let other_hex = "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
    let other_point: Vec<_> = (0..other_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&other_hex[i..i + 2], 16).unwrap())
        .collect();
    let other = envelope::recipient(&other_point).unwrap();
    ok(cmd(dir)
        .args(["s", "recipients", "add", "other", &other, "--json"])
        .output()
        .unwrap());
    let server = mock_agent(dir, vec![Ok(b"a".to_vec()), Ok(b"b".to_vec())]);
    assert_eq!(
        ok(cmd(dir)
            .args(["s", "reencrypt", "--recipient", "other", "--json"])
            .output()
            .unwrap())["count"],
        2
    );
    server.join().unwrap();
    assert_ne!(fs::read(dir.join("seccy.toml")).unwrap(), before);
    let out = cmd(dir)
        .args(["s", "recipients", "remove", "other", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    ok(cmd(dir)
        .args(["s", "recipients", "remove", "mac", "--json"])
        .output()
        .unwrap());
    let listing = ok(cmd(dir).args(["s", "list", "--json"]).output().unwrap());
    assert_eq!(listing["secrets"][0]["recipients"], json!(["other"]));
    let out = cmd(dir)
        .args(["s", "get", "FIRST", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("no enrolled local prompt key"));
}
#[test]
fn invalid_input_cannot_replace_existing_config() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let dir = dir.path();
    initialize(dir);
    let before = fs::read(dir.join("seccy.toml")).unwrap();
    for args in [
        vec!["s", "set", "BAD-NAME", "--from-stdin", "--json"],
        vec![
            "s",
            "set",
            "GOOD",
            "--from-stdin",
            "--recipient",
            "unknown",
            "--json",
        ],
        vec![
            "s",
            "set",
            "GOOD",
            "--from-stdin",
            "--from-file",
            "missing",
            "--json",
        ],
        vec!["s", "exec", "--json", "--", "true"],
    ] {
        let out = cmd(dir).args(args).output().unwrap();
        assert!(!out.status.success(), "{out:?}");
        assert_eq!(fs::read(dir.join("seccy.toml")).unwrap(), before);
    }
    let input = dir.join("input");
    fs::write(&input, b"file bytes\n").unwrap();
    ok(cmd(dir)
        .args(["s", "set", "FILE_VALUE", "--from-file"])
        .arg(input)
        .arg("--json")
        .output()
        .unwrap());
}
