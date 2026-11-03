use std::process::Command;

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
