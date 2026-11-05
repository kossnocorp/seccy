use std::{fs, path::Path, process::Command};

fn run(bin: &Path, dir: &Path, flags: &[&str]) -> std::process::Output {
    Command::new(bin)
        .args(["fnox", "info"])
        .args(flags)
        .current_dir(dir)
        .env("LOG_LEVEL", "off")
        .output()
        .unwrap()
}

#[test]
fn bundled_plugin_can_be_located_after_relocation_and_through_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("Seccy.app");
    let contents = original.join("Contents");
    fs::create_dir_all(contents.join("MacOS")).unwrap();
    fs::create_dir_all(contents.join("Resources/fnox")).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_seccy"), contents.join("MacOS/seccy")).unwrap();
    fs::write(
        contents.join("Resources/fnox/provider.lua"),
        include_str!("../../fnox/provider.lua"),
    )
    .unwrap();
    let moved = temp.path().join("Moved App.app");
    fs::rename(original, &moved).unwrap();
    let link = temp.path().join("seccy");
    std::os::unix::fs::symlink(moved.join("Contents/MacOS/seccy"), &link).unwrap();
    // Information commands must not parse the user's secrets configuration.
    fs::write(temp.path().join("seccy.toml"), "invalid = [").unwrap();
    let plugin = moved
        .canonicalize()
        .unwrap()
        .join("Contents/Resources/fnox");
    let provider = plugin.join("provider.lua");
    let result = run(&link, temp.path(), &["--json"]);
    assert!(result.status.success(), "{result:?}");
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "ok": true, "plugin_dir": plugin, "provider_path": provider,
        })
    );
    for (flags, expected) in [
        (
            vec!["--jq", ".plugin_dir"],
            format!("{}\n", serde_json::json!(plugin)),
        ),
        (
            vec!["--json", "--jq-raw", ".plugin_dir"],
            format!("{}\n", plugin.display()),
        ),
        (
            vec![],
            format!(
                "Plugin directory: {}\nProvider file: {}\n",
                plugin.display(),
                provider.display()
            ),
        ),
    ] {
        let result = run(&link, temp.path(), &flags);
        assert!(result.status.success(), "{result:?}");
        assert_eq!(String::from_utf8(result.stdout).unwrap(), expected);
    }
    fs::remove_file(provider).unwrap();
    let result = run(&link, temp.path(), &["--json"]);
    assert!(!result.status.success());
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["ok"], false);
    assert!(
        value["error"]
            .as_str()
            .unwrap()
            .contains("provider is missing")
    );
}

#[test]
fn unpackaged_binary_reports_actionable_error() {
    let temp = tempfile::tempdir().unwrap();
    let result = run(
        Path::new(env!("CARGO_BIN_EXE_seccy")),
        temp.path(),
        &["--json"],
    );
    assert!(!result.status.success());
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["ok"], false);
    assert!(
        value["error"]
            .as_str()
            .unwrap()
            .contains("packaged Seccy.app")
    );
}
