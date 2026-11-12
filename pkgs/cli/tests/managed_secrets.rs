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
        .env_remove("SECCY_IDENTITY")
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
) -> std::thread::JoinHandle<Vec<Value>> {
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
        let mut requests = Vec::new();
        let mut responses = responses.into_iter();
        while let Some(response) = responses.next() {
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
            assert_eq!(request["key"], "test-key");
            let response = if request["operation"] == "decrypt-managed-batch" {
                let entries: Vec<Value> =
                    serde_json::from_str(request["value"].as_str().unwrap()).unwrap();
                let mut batch = vec![response];
                for _ in 1..entries.len() {
                    batch.push(responses.next().expect("missing batch response"));
                }
                match batch.into_iter().collect::<Result<Vec<_>, _>>() {
                    Ok(values) => {
                        json!({"ok":true,"values_base64":values.into_iter().map(|v| B64.encode(v)).collect::<Vec<_>>()})
                    }
                    Err(error) => json!({"ok":false,"error":error}),
                }
            } else {
                assert_eq!(request["operation"], "decrypt-managed");
                match response {
                    Ok(bytes) => json!({"ok":true,"value_base64":B64.encode(bytes)}),
                    Err(error) => json!({"ok":false,"error":error}),
                }
            };
            requests.push(request);
            seccy_core::agent::write_frame(&mut stream, &serde_json::to_vec(&response).unwrap())
                .unwrap();
        }
        fs::remove_file(socket).unwrap();
        requests
    })
}
#[test]
fn identity_flags_and_environment_precedence_are_strict() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let dir = dir.path();
    initialize(dir);
    set(dir, "TOKEN", b"secret");
    let server = mock_agent(dir, vec![Ok(b"secret".to_vec()); 4]);
    for args in [
        vec!["s", "get", "TOKEN", "-i", "test-key"],
        vec!["s", "-i", "test-key", "get", "TOKEN"],
        vec!["s", "get", "TOKEN", "--identity", "test-key"],
    ] {
        let output = cmd(dir).args(args).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"secret");
    }
    let output = cmd(dir)
        .env("SECCY_IDENTITY", "test-key")
        .args(["s", "get", "TOKEN", "-i", "missing-key"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"secret");
    assert_eq!(server.join().unwrap().len(), 4);
    // Neither an unknown selection nor an empty environment value may fall back.
    for selected in ["missing-key", "", " "] {
        let output = cmd(dir)
            .env("SECCY_IDENTITY", selected)
            .args(["s", "get", "TOKEN", "-i", "test-key", "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{output:?}");
        let body: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(body["ok"], false);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("value_base64"));
    }
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
            "x",
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
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 1, "exec must use one authorization request");
    let entries: Value = serde_json::from_str(requests[0]["value"].as_str().unwrap()).unwrap();
    assert_eq!(entries[0]["name"], "FIRST");
    assert_eq!(entries[1]["name"], "SECOND");
    for responses in [
        vec![Ok(b"a".to_vec()), Err("cancelled")],
        vec![Ok(b"a".to_vec()), Ok(b"invalid\0value".to_vec())],
    ] {
        let server = mock_agent(dir, responses);
        let out = cmd(dir)
            .args([
                "s",
                "x",
                "FIRST",
                "SECOND",
                "--",
                "/usr/bin/touch",
                "SHOULD_NOT_EXIST",
            ])
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(!dir.join("SHOULD_NOT_EXIST").exists());
        assert_eq!(server.join().unwrap().len(), 1);
    }
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

fn write_scope(path: &Path, values: &[(&str, &str)]) -> Value {
    let public = envelope::from_identity(&identity()).unwrap();
    let mut secrets = serde_json::Map::new();
    for (name, value) in values {
        let encrypted = envelope::encrypt(
            name,
            value.as_bytes(),
            std::slice::from_ref(&public),
            seccy_macos::wrap_secret_key,
        )
        .unwrap();
        secrets.insert(
            (*name).into(),
            json!({"recipients":["mac"], "value":encrypted}),
        );
    }
    let data = json!({"recipients":{"mac":public}, "secrets":secrets});
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path, toml::to_string(&data).unwrap()).unwrap();
    data
}

#[test]
fn hierarchy_and_explicit_short_flags_read_and_update_only_selected_scope() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let root = dir.path().canonicalize().unwrap();
    let parent = root.join("project");
    let cwd = parent.join("nested");
    fs::create_dir_all(&cwd).unwrap();
    let global = cwd.join("config/seccy/secrets.toml");
    let parent_file = parent.join("seccy.toml");
    let local = cwd.join("seccy.toml");
    let global_data = write_scope(&global, &[("ASD", "global"), ("GLOBAL_ONLY", "g")]);
    write_scope(&parent_file, &[("ASD", "parent"), ("PARENT_ONLY", "p")]);
    let local_data = write_scope(&local, &[("ASD", "local"), ("LOCAL_ONLY", "l")]);
    let merged = ok(cmd(&cwd).args(["s", "list", "--json"]).output().unwrap());
    assert_eq!(merged["secrets"].as_array().unwrap().len(), 4);
    assert_eq!(merged["secrets"][0]["source"], local.to_str().unwrap());
    for flag in ["-g", "--global"] {
        let isolated = ok(cmd(&cwd)
            .args(["s", "list", flag, "--json"])
            .output()
            .unwrap());
        assert_eq!(isolated["secrets"].as_array().unwrap().len(), 2);
        assert_eq!(isolated["secrets"][0]["source"], global.to_str().unwrap());
    }
    for flag in ["-s", "--secrets", "--file"] {
        let isolated = ok(cmd(&cwd)
            .args(["s", "list", flag])
            .arg(&parent_file)
            .arg("--json")
            .output()
            .unwrap());
        assert_eq!(isolated["secrets"].as_array().unwrap().len(), 2);
        assert_eq!(
            isolated["secrets"][0]["source"],
            parent_file.to_str().unwrap()
        );
    }
    let server = mock_agent(&cwd, vec![Ok(b"global".to_vec()), Ok(b"local".to_vec())]);
    let out = cmd(&cwd).args(["s", "get", "-g", "ASD"]).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, b"global");
    let out = cmd(&cwd)
        .args(["s", "get", "-s"])
        .arg(&local)
        .arg("ASD")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, b"local");
    let requests = server.join().unwrap();
    for (request, expected) in requests.iter().zip([global_data, local_data]) {
        let body: Value = serde_json::from_str(request["value"].as_str().unwrap()).unwrap();
        assert_eq!(body["value"], expected["secrets"]["ASD"]["value"]);
    }
    let before = fs::read(&local).unwrap();
    ok(cmd(&cwd)
        .args(["s", "set", "-g", "NEW", "--from-stdin", "--json"])
        .output()
        .unwrap());
    assert_eq!(fs::read(&local).unwrap(), before);
    let before_global = fs::read(&global).unwrap();
    ok(cmd(&cwd)
        .args(["s", "set", "-s"])
        .arg(&local)
        .args(["NEW_LOCAL", "--from-stdin", "--json"])
        .output()
        .unwrap());
    assert_eq!(fs::read(&global).unwrap(), before_global);
    for args in [
        vec!["s", "set", "ASD", "--from-stdin", "--json"],
        vec!["s", "enroll", "test-key", "--json"],
        vec!["s", "list", "-g", "-s", "other", "--json"],
    ] {
        let output = cmd(&cwd).args(args).output().unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("--secrets"));
    }
}

// Real controlling-terminal test: /dev/tty must be distinct from piped secret input.
fn pick_file(dir: &Path, args: &[&str], keys: &[u8], input: &[u8]) -> Output {
    use std::{
        io::Read,
        os::fd::{AsRawFd, FromRawFd},
        os::unix::process::CommandExt,
    };
    let mut master = -1;
    let mut slave = -1;
    let mut size = libc::winsize {
        ws_row: 24,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        },
        0
    );
    let mut master = unsafe { fs::File::from_raw_fd(master) };
    let slave = unsafe { fs::File::from_raw_fd(slave) };
    let mut command = cmd(dir);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(slave.try_clone().unwrap()));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(2, libc::TIOCSCTTY.into(), 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut screen = Vec::new();
    while !String::from_utf8_lossy(&screen).contains("recipients:") {
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 50) } > 0 {
            let mut buf = [0; 4096];
            let n = master.read(&mut buf).unwrap();
            screen.extend_from_slice(&buf[..n]);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!(
                "picker did not render: {}",
                String::from_utf8_lossy(&screen)
            );
        }
    }
    assert!(String::from_utf8_lossy(&screen).contains("recipients:"));
    master.write_all(keys).unwrap();
    while child.try_wait().unwrap().is_none() {
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 10) } > 0 {
            let mut buf = [0; 4096];
            let n = master.read(&mut buf).unwrap();
            screen.extend_from_slice(&buf[..n]);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!(
                "picker did not complete: {}",
                String::from_utf8_lossy(&screen)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn arrow_picker_isolated_selection_and_cancellation_preserve_other_files() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let cwd = dir.path();
    let global = cwd.join("config/seccy/secrets.toml");
    let local = cwd.join("seccy.toml");
    write_scope(&global, &[("GLOBAL_ONLY", "global")]);
    write_scope(&local, &[("LOCAL_ONLY", "local")]);
    let local_before = fs::read(&local).unwrap();
    let output = pick_file(
        cwd,
        &["s", "set", "PIPED", "--from-stdin"],
        b"\x1b[B\r",
        b"secret input, not picker input",
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(&local).unwrap(), local_before);
    let global_after = fs::read(&global).unwrap();
    assert!(String::from_utf8_lossy(&global_after).contains("PIPED"));
    assert!(!String::from_utf8_lossy(&global_after).contains("LOCAL_ONLY"));
    assert!(!String::from_utf8_lossy(&global_after).contains("secret input, not picker input"));
    let output = pick_file(cwd, &["s", "recipients", "remove", "mac"], b"\x1b", b"");
    assert!(!output.status.success());
    assert_eq!(fs::read(&local).unwrap(), local_before);
    assert_eq!(fs::read(&global).unwrap(), global_after);
    let output = pick_file(cwd, &["s", "remove", "GLOBAL_ONLY"], b"\x1b[B\x1b[A\r", b"");
    assert!(!output.status.success());
    assert_eq!(fs::read(&global).unwrap(), global_after);
}
