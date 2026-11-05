use std::process::{Command, Output, Stdio};

fn run(args: &[&str]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_seccy"))
        .args(args)
        .current_dir(dir.path())
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("LOG_LEVEL", "off")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn query_filters_help_and_parse_errors() {
    let help = run(&["--jq", ".text | contains(\"--jq\")", "--help"]);
    assert!(help.status.success());
    assert_eq!(help.stdout, b"true\n");
    let error = run(&["unknown", "--json", "--jq=.ok"]);
    assert!(!error.status.success());
    assert_eq!(error.stdout, b"false\n");
    assert!(error.stderr.is_empty());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn queries_override_json_and_preserve_jq_stream_semantics() {
    for flags in [vec!["list"], vec!["--json", "list"], vec!["list", "--json"]] {
        for (query, expected) in [
            (".keys | length", "0\n"),
            (".keys[]", ""),
            ("empty", ""),
            (".missing", "null\n"),
            (
                ".ok, false, null, \"hello\"",
                "true\nfalse\nnull\n\"hello\"\n",
            ),
            ("[1,2,3] | map(select(. > 1) * 2)", "[\n  4,\n  6\n]\n"),
            ("def twice: . * 2; 3 | twice", "6\n"),
            ("\"abc\" | test(\"^a\")", "true\n"),
        ] {
            let mut args = flags.clone();
            args.extend(["--jq", query]);
            let result = run(&args);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(result.stdout, expected.as_bytes(), "{args:?}");
            assert!(result.stderr.is_empty());
        }
    }
    for args in [
        vec!["get", "missing", "--jq", ".key"],
        vec!["--jq", ".keys | length", "sync"],
        vec!["provision", "--jq", ".keys | length"],
        vec!["service", "status", "--jq", ".ok"],
    ] {
        let result = run(&args);
        assert!(
            result.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(serde_json::from_slice::<serde_json::Value>(&result.stdout).is_ok());
    }
}

#[test]
fn invalid_queries_fail_before_command_execution() {
    for query in [".[", "unknown_function"] {
        let result = run(&["reset", "--yes", "--json", "--jq", query]);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("query:"));
    }
}

#[test]
fn raw_queries_handle_strings_json_and_parser_responses() {
    let result = run(&[
        "--help",
        "--json",
        "--jq-raw",
        r#""hello\n\"world\"", "", null, false, 42, {a: "b"}, empty"#,
    ]);
    assert!(result.status.success());
    assert_eq!(
        result.stdout,
        b"hello\n\"world\"\n\nnull\nfalse\n42\n{\n  \"a\": \"b\"\n}\n"
    );
    let result = run(&["unknown", "--jq-raw=\"raw error\""]);
    assert!(!result.status.success());
    assert_eq!(result.stdout, b"raw error\n");
    let result = run(&["reset", "--yes", "--jq-raw", ".["]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("query:"));
    let result = run(&["--help", "--jq", ".", "--jq-raw", "."]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("cannot be used together"));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn raw_queries_work_on_command_results() {
    for args in [
        vec!["list", "--json", "--jq-raw", "\"public key\", .ok"],
        vec!["--jq-raw", "\"public key\", .ok", "get", "missing"],
    ] {
        let result = run(&args);
        assert!(result.status.success());
        assert_eq!(result.stdout, b"public key\ntrue\n");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn command_errors_are_filtered_but_query_errors_are_not() {
    for command in [
        vec!["remove", "missing"],
        vec!["reset"],
        vec!["encrypt", "missing"],
        vec!["crypto-check", "missing"],
    ] {
        let mut args = command;
        args.extend(["--jq", ".ok"]);
        let result = run(&args);
        assert!(!result.status.success());
        assert_eq!(result.stdout, b"false\n");
    }
    let result = run(&["list", "--jq", "1, error(\"oops\")"]);
    assert!(!result.status.success());
    assert_eq!(result.stdout, b"1\n");
    assert!(String::from_utf8_lossy(&result.stderr).contains("oops"));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn agent_filters_ready_and_request_error_events() {
    use std::{
        io::{BufRead, BufReader},
        os::unix::net::UnixStream,
    };
    struct Agent(std::process::Child);
    impl Drop for Agent {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut agent = Agent(
        Command::new(env!("CARGO_BIN_EXE_seccy"))
            .args(["agent", "--json", "--jq", ".event"])
            .env("XDG_RUNTIME_DIR", dir.path())
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .env("LOG_LEVEL", "off")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stdout = BufReader::new(agent.0.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "\"ready\"\n");
    std::fs::write(dir.path().join("state/seccy/state.toml"), "invalid = [").unwrap();
    let mut socket = UnixStream::connect(dir.path().join("seccy/agent.sock")).unwrap();
    seccy_core::agent::write_frame(&mut socket, &[11]).unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "\"request_error\"\n");
}

#[test]
fn exit_status_queries_use_last_result_for_commands_and_help() {
    for prefix in [vec!["fnox", "init"], vec!["--help"]] {
        for (query, expected, code) in [
            ("null", "null\n", 1),
            ("false", "false\n", 1),
            ("empty", "", 4),
            ("true", "true\n", 0),
            ("0", "0\n", 0),
            ("\"\"", "\"\"\n", 0),
            ("[]", "[]\n", 0),
            ("{}", "{}\n", 0),
            ("false, true", "false\ntrue\n", 0),
            ("true, null", "true\nnull\n", 1),
            ("true, empty", "true\n", 0),
        ] {
            let mut args = prefix.clone();
            args.extend(["--json", "--jq-exit-status", query]);
            let result = run(&args);
            assert_eq!(result.status.code(), Some(code), "{args:?}: {result:?}");
            assert_eq!(result.stdout, expected.as_bytes());
            assert!(result.stderr.is_empty(), "{result:?}");
        }
    }
    let result = run(&["--jq-exit-status=.version != null", "fnox", "init"]);
    assert_eq!(result.status.code(), Some(0));
    assert_eq!(result.stdout, b"true\n");
}

#[test]
fn exit_status_queries_preserve_errors_and_reject_conflicting_flags() {
    for args in [
        vec!["unknown", "--jq-exit-status=true"],
        vec!["fnox", "info", "--jq-exit-status", "true"],
    ] {
        let result = run(&args);
        assert!(!result.status.success());
        assert_eq!(result.stdout, b"true\n");
    }
    for query in [".[", "unknown_function", "true, error(\"oops\")"] {
        let result = run(&["--help", "--jq-exit-status", query]);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("query:"));
    }
    for flag in ["--jq", "--jq-raw"] {
        for prefix in [vec!["--help"], vec!["fnox", "init"]] {
            let mut args = prefix;
            args.extend([flag, ".", "--jq-exit-status", "."]);
            let result = run(&args);
            assert!(!result.status.success());
            assert!(String::from_utf8_lossy(&result.stderr).contains("cannot be used together"));
        }
    }
}
