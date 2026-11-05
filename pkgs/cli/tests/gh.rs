#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::{
    fs,
    process::{Command, Stdio},
};

#[test]
fn gh_wrapper_confirmation_pagination_and_verbatim_errors() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake gh.sh");
    fs::write(&script, r#"
test "$1" = wrapper || exit 91
shift
printf '%s\n' "$*" >> "$CALLS"
case "$*" in
  *--jq*) ;;
  *) exit 92 ;;
esac
if test "$FAIL" = yes; then
  printf 'raw stdout\nwithout newline'
  printf 'raw stderr\nwithout newline' >&2
  exit 42
fi
case "$*" in
  *DELETE*) printf 'hidden mutation output' ;;
  *user/ssh_signing_keys*) ;;
  *) printf '{"id":42,"title":"%s@%s/seccy/stale","key":"ssh-type AAA"}\n' "$(whoami)" "$(hostname)" ;;
esac
"#).unwrap();
    let calls = dir.path().join("calls");
    let run = |flags: &[&str], fail: bool| {
        Command::new(env!("CARGO_BIN_EXE_seccy"))
            .args(["gh", "sync", "--cmd"])
            .arg(format!("/bin/sh '{}' wrapper", script.display()))
            .args(flags)
            .current_dir(dir.path())
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .env("CALLS", &calls)
            .env("FAIL", if fail { "yes" } else { "no" })
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let result = run(&[], false);
    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("Remove auth key"));
    assert!(stderr.contains("confirmation requires a terminal"));
    assert!(!fs::read_to_string(&calls).unwrap().contains("DELETE"));
    for flag in ["-y", "--yes"] {
        fs::write(&calls, "").unwrap();
        let result = run(&[flag, "--json"], false);
        assert!(result.status.success(), "{:?}", result);
        let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["plan"]["remove"][0]["id"], 42);
        assert!(String::from_utf8_lossy(&result.stderr).contains("Remove auth key"));
        let calls = fs::read_to_string(&calls).unwrap();
        assert_eq!(calls.lines().count(), 3);
        assert_eq!(calls.matches("--paginate").count(), 2);
        assert!(calls.contains("user/keys/42 --method DELETE"));
    }
    let result = run(&["--yes", "--json"], true);
    assert!(!result.status.success());
    assert_eq!(result.stdout, b"raw stdout\nwithout newline");
    assert_eq!(result.stderr, b"raw stderr\nwithout newline");
}
