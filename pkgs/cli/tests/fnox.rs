use std::{fs, path::Path, process::Command};

fn run(bin: &Path, dir: &Path, flags: &[&str]) -> std::process::Output {
    command(bin, dir, "info", flags)
}

fn command(bin: &Path, dir: &Path, subcommand: &str, flags: &[&str]) -> std::process::Output {
    Command::new(bin)
        .args(["fnox", subcommand])
        .args(flags)
        .current_dir(dir)
        .env("LOG_LEVEL", "off")
        .env("HOME", dir)
        .env_remove("XDG_DATA_HOME")
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
            "version": env!("CARGO_PKG_VERSION"), "binary_version": env!("CARGO_PKG_VERSION"),
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
                "Plugin directory: {}\nProvider file: {}\nPlugin version: {}\nBinary version: {}\n",
                plugin.display(),
                provider.display(),
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_VERSION")
            ),
        ),
    ] {
        let result = run(&link, temp.path(), &flags);
        assert!(result.status.success(), "{result:?}");
        assert_eq!(String::from_utf8(result.stdout).unwrap(), expected);
    }
    let result = command(&link, temp.path(), "init", &["--json"]);
    assert!(result.status.success(), "{result:?}");
    let installed = temp.path().join(".local/share/seccy/fnox");
    let result = run(&link, temp.path(), &["--jq-raw", ".plugin_dir"]);
    assert!(result.status.success());
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        format!("{}\n", installed.display())
    );
    fs::remove_file(installed.join("provider.lua")).unwrap();
    assert!(run(&link, temp.path(), &["--json"]).status.success());
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

#[test]
fn standalone_init_installs_embedded_source_and_updates_existing_plugin() {
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("standalone-seccy");
    fs::copy(env!("CARGO_BIN_EXE_seccy"), &bin).unwrap();
    fs::write(temp.path().join("seccy.toml"), "invalid = [").unwrap();
    let provider = temp.path().join(".local/share/seccy/fnox/provider.lua");
    for flags in [
        vec!["--json"],
        vec!["--jq", ".ok"],
        vec!["--jq-raw", ".provider_path"],
    ] {
        let result = command(&bin, temp.path(), "init", &flags);
        assert!(result.status.success(), "{result:?}");
        assert_eq!(
            fs::read(&provider).unwrap(),
            include_bytes!("../../fnox/provider.lua")
        );
        assert!(run(&bin, temp.path(), &["--json"]).status.success());
        fs::write(&provider, "old version").unwrap();
    }
}

#[test]
fn init_and_info_respect_xdg_data_home() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("custom data");
    for subcommand in ["init", "info"] {
        let result = Command::new(env!("CARGO_BIN_EXE_seccy"))
            .args(["fnox", subcommand, "--jq-raw", ".plugin_dir"])
            .env("HOME", temp.path())
            .env("XDG_DATA_HOME", &data)
            .env("LOG_LEVEL", "off")
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
        assert_eq!(
            String::from_utf8(result.stdout).unwrap(),
            format!("{}\n", data.join("seccy/fnox").display())
        );
    }
    assert!(!temp.path().join(".local").exists());
}

#[test]
fn installed_version_is_persisted_read_and_refreshed() {
    let temp = tempfile::tempdir().unwrap();
    let bin = Path::new(env!("CARGO_BIN_EXE_seccy"));
    let metadata = temp.path().join(".local/share/seccy/fnox/metadata.json");
    assert!(
        command(bin, temp.path(), "init", &["--json"])
            .status
            .success()
    );
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&metadata).unwrap()).unwrap();
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    fs::write(&metadata, r#"{"version":"0.0.1"}"#).unwrap();
    let result = run(bin, temp.path(), &["--json"]);
    assert!(result.status.success());
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["version"], "0.0.1");
    assert_eq!(value["binary_version"], env!("CARGO_PKG_VERSION"));
    let result = run(bin, temp.path(), &["--jq-raw", ".version"]);
    assert!(result.status.success());
    assert_eq!(result.stdout, b"0.0.1\n");
    fs::remove_file(&metadata).unwrap();
    let result = run(bin, temp.path(), &["--jq", ".version"]);
    assert!(result.status.success());
    assert_eq!(result.stdout, b"null\n");
    fs::write(&metadata, "invalid json").unwrap();
    let result = run(bin, temp.path(), &["--json"]);
    assert!(!result.status.success());
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains("run seccy fnox init")
    );
    let result = command(bin, temp.path(), "init", &["--jq-raw", ".version"]);
    assert!(result.status.success());
    assert_eq!(
        result.stdout,
        format!("{}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );
}
