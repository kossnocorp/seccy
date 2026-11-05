use std::process::Command;

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn destructive_commands_require_confirmation_and_accept_both_yes_flags() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state/seccy");
    std::fs::create_dir_all(&state_dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A malformed registry stops confirmed commands before any Keychain mutation.
    let registry = state_dir.join("state.toml");
    std::fs::write(&registry, "invalid = [").unwrap();
    let config = dir.path().join("seccy.toml");
    std::fs::write(&config, "[keys.example]\nmode = 'notify'\n").unwrap();
    for command in [vec!["remove", "example"], vec!["reset"]] {
        for flag in [None, Some("-y"), Some("--yes")] {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_seccy"));
            cmd.args(&command)
                .arg("--json")
                .current_dir(dir.path())
                .env("XDG_STATE_HOME", dir.path().join("state"))
                .stdin(std::process::Stdio::null());
            if let Some(flag) = flag {
                cmd.arg(flag);
            }
            let result = cmd.output().unwrap();
            assert!(!result.status.success());
            let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            let error = value["error"].as_str().unwrap();
            assert!(
                error.contains(if flag.is_some() {
                    "invalid seccy state.toml"
                } else {
                    "confirmation requires a terminal"
                }),
                "{error}"
            );
            assert!(result.stderr.is_empty());
            assert_eq!(std::fs::read_to_string(&registry).unwrap(), "invalid = [");
            assert_eq!(
                std::fs::read_to_string(&config).unwrap(),
                "[keys.example]\nmode = 'notify'\n"
            );
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn inventory_survives_missing_source_and_merges_another_config() {
    let dir = tempfile::tempdir().unwrap();
    let paths = seccy_core::storage::Paths::resolve(Some(dir.path()), |_| None).unwrap();
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&paths.state)
        .unwrap();
    let mut state = seccy_core::state::State::default();
    state.overlay(
        &seccy_core::Config::parse("[keys.seccy_inventory_missing_fixture]\nmode='notify'")
            .unwrap(),
        &dir.path().join("deleted-source.toml"),
    );
    state.save(&paths).unwrap();
    std::fs::write(
        dir.path().join("seccy.toml"),
        "[keys.seccy_inventory_config_fixture]\nmode='notify'",
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_seccy"))
        .args(["list", "--json"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_STATE_HOME", dir.path().join(".local/state"))
        .env("XDG_DATA_HOME", dir.path().join(".local/share"))
        .env("LOG_LEVEL", "debug")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let keys = value["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["config"], "~/seccy.toml");
    assert_eq!(keys[1]["config"], "~/deleted-source.toml");
    assert_eq!(keys[1]["status"], "not_provisioned");
    assert_eq!(
        seccy_core::state::State::load(&paths).unwrap().keys.len(),
        1
    );
    let log = std::fs::read_to_string(paths.state.join("logs/seccy.jsonl")).unwrap();
    let events: Vec<serde_json::Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let fields = |name: &str| {
        events
            .iter()
            .find(|event| event["fields"]["event"] == name)
            .unwrap()["fields"]
            .clone()
    };
    let stored: serde_json::Value =
        serde_json::from_str(fields("state_loaded")["state_json"].as_str().unwrap()).unwrap();
    assert_eq!(stored["keys"].as_object().unwrap().len(), 1);
    assert_eq!(
        stored["keys"]["seccy_inventory_missing_fixture"]["config"],
        dir.path().join("deleted-source.toml").to_str().unwrap()
    );
    let merged: serde_json::Value =
        serde_json::from_str(fields("inventory_view")["state_json"].as_str().unwrap()).unwrap();
    assert_eq!(merged["keys"].as_object().unwrap().len(), 2);
    let displayed: serde_json::Value =
        serde_json::from_str(fields("inventory_result")["result_json"].as_str().unwrap()).unwrap();
    assert_eq!(displayed, value);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn decrypt_cli_preserves_binary_and_newlines_without_logging_payloads() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{
        io::Write,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        process::Stdio,
    };
    for (json_mode, query) in [(false, false), (true, false), (false, true), (true, true)] {
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
        if query {
            command.args(["--jq", ".value_base64"]);
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
        if query {
            let value: String = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(STANDARD.decode(value).unwrap(), payload);
        } else if json_mode {
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
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
    // The same process notices registry updates, fails closed on malformed state,
    // and recovers after an atomic replacement without a restart.
    let registry = dir.path().join("state/seccy/state.toml");
    for (text, expected) in [
        ("broken = [", "invalid seccy state.toml"),
        ("[keys]\n", "key is not configured and provisioned"),
    ] {
        let temporary = registry.with_extension("new");
        std::fs::write(&temporary, text).unwrap();
        std::fs::rename(&temporary, &registry).unwrap();
        let mut stream = UnixStream::connect(socket).unwrap();
        seccy_core::agent::write_frame(
            &mut stream,
            br#"{"operation":"check","key":"missing","value":null}"#,
        )
        .unwrap();
        let response = seccy_core::agent::read_frame(&mut stream).unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert!(
            value["error"].as_str().unwrap().contains(expected),
            "{value}"
        );
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
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
