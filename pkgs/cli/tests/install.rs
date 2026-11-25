//! Exercise installer replacement/integration decisions without touching the host.
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/bash\nset -eu\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn source_install_replaces_same_version_without_service_or_fnox_integration() {
    for force in [false, true] {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let home = root.join("home");
        let tools = root.join("tools");
        let payload = root.join("payload/Seccy.app/Contents/MacOS");
        let installed = home.join(".local/share/seccy/Seccy.app/Contents/MacOS");
        for dir in [
            &tools,
            &payload,
            &installed,
            &home.join("Library/LaunchAgents"),
        ] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(
            home.join("Library/LaunchAgents/fyi.seccy.agent.plist"),
            "existing service",
        )
        .unwrap();
        script(
            &installed.join("seccy"),
            "if [[ $1 == --version ]]; then echo 'seccy 1.0.0'; else exit 99; fi\n# old",
        );
        script(
            &payload.join("seccy"),
            "if [[ $1 == --version ]]; then echo 'seccy 1.0.0'; else echo unexpected >> \"$CALLS\"; exit 99; fi\n# new",
        );
        script(
            &tools.join("uname"),
            "case \"$1\" in -s) echo Darwin;; -m) echo arm64;; esac",
        );
        script(&tools.join("id"), "echo 501");
        for name in ["codesign", "xcrun", "spctl"] {
            script(&tools.join(name), "exit 0");
        }
        script(&tools.join("fnox"), "echo fnox >> \"$CALLS\"; exit 99");
        script(
            &tools.join("ditto"),
            "if [[ $1 == -x ]]; then cp -R \"$PAYLOAD/Seccy.app\" \"$4/Seccy.app\"; else cp -R \"$1\" \"$2\"; fi",
        );
        let archive = root.join("source.zip");
        fs::write(&archive, "stub archive").unwrap();
        let calls = root.join("calls");
        let mut command = Command::new("/bin/bash");
        command
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/install.sh"
            ))
            .arg("--archive")
            .arg(archive)
            .arg("--no-integrate")
            .env("HOME", &home)
            .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
            .env("PAYLOAD", root.join("payload"))
            .env("CALLS", &calls)
            .env_remove("XDG_BIN_HOME")
            .env_remove("XDG_DATA_HOME");
        if force {
            command.arg("--force");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let contents = fs::read_to_string(installed.join("seccy")).unwrap();
        assert!(contents.contains(if force { "# new" } else { "# old" }));
        assert!(!calls.exists(), "service/fnox integration must not run");
        assert_eq!(
            fs::read_to_string(home.join("Library/LaunchAgents/fyi.seccy.agent.plist")).unwrap(),
            "existing service"
        );
        if force {
            assert_eq!(
                fs::read_link(home.join(".local/bin/seccy")).unwrap(),
                installed.join("seccy")
            );
        }
    }
}
