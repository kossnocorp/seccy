use std::{path::Path, process::Command};

fn activate(home: &Path, shell: Option<&str>, detected: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_seccy"));
    command.arg("activate");
    if let Some(shell) = shell {
        command.arg(shell);
    }
    command.env_remove("SHELL");
    if let Some(detected) = detected {
        command.env("SHELL", detected);
    }
    command
        .env("HOME", home)
        .env(
            "XDG_BIN_HOME",
            home.join("bin ' $dollar `tick` \\ backslash"),
        )
        .env(
            "XDG_RUNTIME_DIR",
            home.join("runtime ' $dollar `tick` \\ backslash"),
        )
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        // Activation must bypass logging entirely.
        .env("LOG_LEVEL", "invalid")
        .output()
        .unwrap()
}

#[test]
fn supports_mise_shells_without_creating_files() {
    let home = tempfile::tempdir().unwrap();
    for shell in [
        "bash",
        "elvish",
        "fish",
        "nu",
        "xonsh",
        "zsh",
        "pwsh",
        "powershell",
    ] {
        let result = activate(home.path(), Some(shell), None);
        assert!(result.status.success(), "{shell}: {result:?}");
        assert!(String::from_utf8_lossy(&result.stdout).contains("SSH_AUTH_SOCK"));
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn detects_shell_and_explicit_choice_takes_precedence() {
    let home = tempfile::tempdir().unwrap();
    let explicit = activate(home.path(), Some("zsh"), None);
    let detected = activate(home.path(), None, Some("/bin/zsh"));
    assert!(detected.status.success());
    assert_eq!(explicit.stdout, detected.stdout);
    assert_eq!(
        explicit.stdout,
        activate(home.path(), Some("zsh"), Some("/bin/fish")).stdout
    );
    assert!(!activate(home.path(), None, None).status.success());
    assert!(
        !activate(home.path(), None, Some("/bin/unsupported"))
            .status
            .success()
    );
    assert!(
        !activate(home.path(), Some("unsupported"), Some("/bin/bash"))
            .status
            .success()
    );
}

#[test]
fn shell_scripts_preserve_literal_paths() {
    let home = tempfile::tempdir().unwrap();
    for shell in ["bash", "zsh", "fish"] {
        if Command::new(shell).arg("--version").output().is_err() {
            continue;
        }
        let result = activate(home.path(), Some(shell), None);
        assert!(result.status.success());
        let mut script = String::from_utf8(result.stdout).unwrap();
        if shell == "fish" {
            script.push_str("printf '%s\\n' \"$PATH[1]\" \"$SSH_AUTH_SOCK\"");
        } else {
            script.push_str("printf '%s\\n' \"${PATH%%:*}\" \"$SSH_AUTH_SOCK\"");
        }
        let result = Command::new(shell).args(["-c", &script]).output().unwrap();
        assert!(result.status.success(), "{shell}: {result:?}");
        let expected = format!(
            "{}/bin ' $dollar `tick` \\ backslash\n{}/runtime ' $dollar `tick` \\ backslash/seccy/agent.sock\n",
            home.path().display(),
            home.path().display()
        );
        assert_eq!(
            String::from_utf8(result.stdout).unwrap(),
            expected,
            "{shell}"
        );
    }
}

#[test]
fn socket_falls_back_to_state_directory() {
    let home = tempfile::tempdir().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_seccy"))
        .args(["activate", "bash"])
        .env("HOME", home.path())
        .env_remove("XDG_BIN_HOME")
        .env("XDG_RUNTIME_DIR", "relative")
        .env("XDG_STATE_HOME", home.path().join("state"))
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    let script = String::from_utf8(result.stdout).unwrap();
    assert!(script.contains(&format!("{}/state/seccy/agent.sock", home.path().display())));
    assert!(script.contains(&format!("{}/.local/bin", home.path().display())));
}
