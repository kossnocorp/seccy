//! Per-user systemd lifecycle. Desktop prompts require the user's GNOME session.
use crate::{Output, ServiceCommand, emit, server};
use anyhow::{Context, Result, ensure};
use seccy_core::storage::Paths;
use serde_json::json;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

const UNIT: &str = "seccy-agent.service";

fn systemctl(args: &[&str]) -> Result<std::process::Output> {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .context("run systemctl --user")
}
fn checked(args: &[&str]) -> Result<()> {
    let output = systemctl(args)?;
    ensure!(
        output.status.success(),
        "systemctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
fn quote(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(char::is_control),
        "service value contains control characters"
    );
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}
fn path(path: &Path) -> Result<String> {
    quote(
        &path
            .to_str()
            .context("service path is not UTF-8")?
            .replace('$', "$$"),
    )
}

fn definition(executable: &Path, paths: &Paths) -> Result<String> {
    let mut unit = format!(
        "[Unit]\nDescription=Seccy TPM/FIDO SSH agent\nPartOf=graphical-session.target\nAfter=graphical-session-pre.target\n\n[Service]\nType=simple\nExecStart={} agent --socket {}\nRestart=on-failure\nRestartSec=5\nUMask=0077\n",
        path(executable)?,
        path(&paths.runtime.join("agent.sock"))?
    );
    let state = paths.state.parent().context("state parent")?;
    unit.push_str(&format!(
        "Environment={}\n",
        quote(&format!(
            "XDG_STATE_HOME={}",
            state.to_str().context("path is not UTF-8")?
        ))?
    ));
    for name in ["LOG_LEVEL", "SECCY_KNOWN_HOSTS"] {
        if let Ok(value) = std::env::var(name) {
            unit.push_str(&format!(
                "Environment={}\n",
                quote(&format!("{name}={value}"))?
            ));
        }
    }
    unit.push_str("\n[Install]\nWantedBy=graphical-session.target\n");
    Ok(unit)
}

pub fn run(command: ServiceCommand, paths: &Paths, output: &Output) -> Result<()> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is required")?);
    ensure!(home.is_absolute(), "HOME must be absolute");
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    let directory = config.join("systemd/user");
    let file = directory.join(UNIT);
    match command {
        ServiceCommand::Install(_) => {
            server::private_dir(&paths.state)?;
            server::private_dir(&paths.runtime)?;
            fs::create_dir_all(&directory)?;
            let executable = fs::canonicalize(std::env::current_exe()?)?;
            let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
            temporary.write_all(definition(&executable, paths)?.as_bytes())?;
            temporary.as_file().sync_all()?;
            temporary.persist(&file)?;
            checked(&["daemon-reload"])?;
            checked(&["enable", "--now", UNIT])?;
            emit(
                output,
                json!({"ok": true, "service": UNIT, "unit": file}),
                "Service installed and started",
            )?;
        }
        ServiceCommand::Uninstall(_) => {
            checked(&["disable", "--now", UNIT])?;
            match fs::remove_file(&file) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
            checked(&["daemon-reload"])?;
            emit(
                output,
                json!({"ok": true, "service": UNIT}),
                "Service uninstalled",
            )?;
        }
        ServiceCommand::Restart(_) => {
            checked(&["restart", UNIT])?;
            emit(
                output,
                json!({"ok": true, "service": UNIT}),
                "Service restarted",
            )?;
        }
        ServiceCommand::Status(_) => {
            let status = systemctl(&["show", UNIT, "--property=LoadState,ActiveState,SubState"])?;
            ensure!(status.status.success(), "cannot query systemd user service");
            let details = String::from_utf8_lossy(&status.stdout);
            let loaded = details.lines().any(|l| l == "LoadState=loaded");
            let running = details.lines().any(|l| l == "SubState=running");
            emit(
                output,
                json!({"ok": true, "installed": file.exists(), "loaded": loaded, "running": running, "details": details}),
                &details,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn systemd_exec_paths_cannot_inject_directives_or_specifiers() {
        assert!(quote("/tmp/a\nExecStart=bad").is_err());
        assert_eq!(
            quote("/tmp/%h/$HOME/\"x\"").unwrap(),
            "\"/tmp/%%h/$HOME/\\\"x\\\"\""
        );
    }
}
