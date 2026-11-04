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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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
