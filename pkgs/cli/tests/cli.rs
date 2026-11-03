use std::process::Command;

#[cfg(target_os = "macos")]
#[test]
fn decrypt_cli_preserves_binary_and_newlines_without_logging_payloads() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{
        io::Write,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        process::Stdio,
    };
    for json_mode in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("secrets.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let payload = b"sensitive-value\0\xff\n\n";
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = seccy_core::agent::read_frame(&mut stream).unwrap().unwrap();
            let value: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(value["operation"], "decrypt");
            assert_eq!(value["key"], "secrets");
            assert_eq!(value["value"], "ciphertext");
            seccy_core::agent::write_frame(
                &mut stream,
                &serde_json::to_vec(
                    &serde_json::json!({"ok":true, "value_base64": STANDARD.encode(payload)}),
                )
                .unwrap(),
            )
            .unwrap();
        });
        let mut command = Command::new(env!("CARGO_BIN_EXE_seccy"));
        command
            .args(["decrypt", "secrets", "--socket"])
            .arg(&socket)
            .arg("--config")
            .arg(dir.path().join("missing.toml"))
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .env("LOG_LEVEL", "trace")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if json_mode {
            command.arg("--json");
        }
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"ciphertext\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        server.join().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if json_mode {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                STANDARD
                    .decode(value["value_base64"].as_str().unwrap())
                    .unwrap(),
                payload
            );
        } else {
            assert_eq!(output.stdout, payload);
        }
        let log = std::fs::read_to_string(dir.path().join("state/seccy/logs/seccy.jsonl")).unwrap();
        assert!(!log.contains("sensitive-value"));
        assert!(!log.contains("ciphertext"));
        assert!(!log.contains(&STANDARD.encode(payload)));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn secrets_agent_rejects_unconfigured_keys_and_untrusted_requests() {
    use std::{
        io::{BufRead, BufReader},
        os::unix::net::UnixStream,
        process::Stdio,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_seccy"))
        .args(["agent", "--json", "--config"])
        .arg(dir.path().join("missing.toml"))
        .env("XDG_RUNTIME_DIR", dir.path())
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Always reap the foreground agent, including if an assertion fails.
    struct Agent(std::process::Child);
    impl Drop for Agent {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let stdout = child.stdout.take().unwrap();
    let _agent = Agent(child);
    let mut ready = String::new();
    BufReader::new(stdout).read_line(&mut ready).unwrap();
    let ready: serde_json::Value = serde_json::from_str(&ready).unwrap();
    let socket = ready["secrets_socket"].as_str().unwrap();
    for request in [
        r#"{"operation":"decrypt","key":"missing","value":"ciphertext"}"#,
        r#"{"untrusted-secret":"never-echo"}"#,
    ] {
        let mut stream = UnixStream::connect(socket).unwrap();
        seccy_core::agent::write_frame(&mut stream, request.as_bytes()).unwrap();
        let bytes = seccy_core::agent::read_frame(&mut stream).unwrap().unwrap();
        let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["ok"], false);
        assert!(!String::from_utf8_lossy(&bytes).contains("never-echo"));
    }
}

#[test]
fn removed_commands_and_parse_errors_are_json() {
    for command in ["unknown", "validate", "public-key"] {
        let output = Command::new(env!("CARGO_BIN_EXE_seccy"))
            .args(["--json", command])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["ok"], false);
        assert!(value["error"].is_string());
        assert!(output.stderr.is_empty());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn missing_config_means_empty_results() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["list"],
        vec!["get", "missing"],
        vec!["sync"],
        vec!["provision"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_seccy"))
            .args(&args)
            .arg("--json")
            .arg("--config")
            .arg(dir.path().join("missing.toml"))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .env("XDG_RUNTIME_DIR", dir.path().join("run"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["ok"], true);
        if args[0] == "get" {
            assert!(value["key"].is_null());
        } else {
            assert_eq!(value["keys"], serde_json::json!([]));
        }
        assert!(output.stderr.is_empty());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn log_file_is_private_and_does_not_pollute_json_stdout() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    for level in ["debug", "off", "invalid"] {
        let state = dir.path().join(level);
        let output = Command::new(env!("CARGO_BIN_EXE_seccy"))
            .args(["list", "--json", "--config"])
            .arg(dir.path().join("missing.toml"))
            .env("LOG_LEVEL", level)
            .env("XDG_STATE_HOME", &state)
            .output()
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["ok"], level != "invalid");
        assert!(output.stderr.is_empty());
        let file = state.join("seccy/logs/seccy.jsonl");
        if level == "debug" {
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let text = std::fs::read_to_string(file).unwrap();
            assert!(
                text.lines()
                    .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
            );
            assert!(text.contains("command_started"));
        } else {
            assert!(!file.exists());
        }
    }
}
