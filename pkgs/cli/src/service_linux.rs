//! Per-user systemd lifecycle. Desktop prompts require the user's GNOME session.
use crate::{Output, ServiceCommand, emit, server};
use anyhow::{Context, Result, ensure};
use seccy_core::storage::Paths;
use serde_json::json;
use std::{fs, io::Write, path::Path, process::Command};

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
    let config = paths
        .config
        .parent()
        .and_then(Path::parent)
        .context("config home")?;
    unit.push_str(&format!(
        "Environment={}\n",
        quote(&format!(
            "XDG_CONFIG_HOME={}",
            config.to_str().context("path is not UTF-8")?
        ))?
    ));
    unit.push_str(&format!(
        "Environment={}\n",
        quote(&format!(
            "XDG_STATE_HOME={}",
            state.to_str().context("path is not UTF-8")?
        ))?
    ));
    if let Ok(value) = std::env::var("SECCY_KNOWN_HOSTS") {
        unit.push_str(&format!(
            "Environment={}\n",
            quote(&format!("SECCY_KNOWN_HOSTS={value}"))?
        ));
    }
    unit.push_str("\n[Install]\nWantedBy=graphical-session.target\n");
    Ok(unit)
}

pub fn run(command: ServiceCommand, paths: &Paths, output: &Output) -> Result<()> {
    let config = paths
        .config
        .parent()
        .and_then(Path::parent)
        .context("config home")?;
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
    fn service_captures_resolved_config_home_but_not_log_level() {
        for config in [None, Some("/custom config"), Some("relative"), Some("")] {
            let paths = Paths::resolve(Some(Path::new("/home/test")), |name| {
                (name == "XDG_CONFIG_HOME")
                    .then(|| config.map(Into::into))
                    .flatten()
            })
            .unwrap();
            let unit = definition(Path::new("/usr/bin/seccy"), &paths).unwrap();
            let expected = if config == Some("/custom config") {
                "/custom config"
            } else {
                "/home/test/.config"
            };
            assert!(unit.contains(&format!("Environment=\"XDG_CONFIG_HOME={expected}\"")));
            assert!(!unit.contains("LOG_LEVEL="));
        }
    }
    #[test]
    fn systemd_exec_paths_cannot_inject_directives_or_specifiers() {
        assert!(quote("/tmp/a\nExecStart=bad").is_err());
        assert_eq!(
            quote("/tmp/%h/$HOME/\"x\"").unwrap(),
            "\"/tmp/%%h/$HOME/\\\"x\\\"\""
        );
    }
}
