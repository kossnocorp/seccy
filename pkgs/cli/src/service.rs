//! Per-user launchd lifecycle; the agent remains a foreground process.
use crate::{ServiceCommand, emit, server};
use anyhow::{Context, Result, ensure};
use seccy_core::storage::Paths;
use serde_json::json;
use std::{
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const LABEL: &str = "fyi.seccy.agent";

fn launchctl(args: &[&str]) -> Result<std::process::Output> {
    Command::new("/bin/launchctl")
        .args(args)
        .output()
        .context("run launchctl")
}

fn checked(args: &[&str]) -> Result<()> {
    let output = launchctl(args)?;
    ensure!(
        output.status.success(),
        "launchctl {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn text(path: &Path) -> Result<&str> {
    path.to_str().context("service paths must be UTF-8")
}

fn definition(executable: &Path, home: &Path, paths: &Paths) -> Result<plist::Value> {
    let mut env = plist::Dictionary::new();
    env.insert("HOME".into(), text(home)?.into());
    env.insert(
        "XDG_CONFIG_HOME".into(),
        text(
            paths
                .config
                .parent()
                .and_then(Path::parent)
                .context("config home")?,
        )?
        .into(),
    );
    env.insert(
        "XDG_STATE_HOME".into(),
        text(paths.state.parent().context("state parent")?)?.into(),
    );
    if let Ok(value) = std::env::var("SECCY_KNOWN_HOSTS") {
        env.insert("SECCY_KNOWN_HOSTS".into(), value.into());
    }
    let mut dict = plist::Dictionary::new();
    dict.insert("Label".into(), LABEL.into());
    dict.insert(
        "ProgramArguments".into(),
        plist::Value::Array(vec![
            text(executable)?.into(),
            "agent".into(),
            "--socket".into(),
            text(&paths.runtime.join("agent.sock"))?.into(),
        ]),
    );
    dict.insert("EnvironmentVariables".into(), env.into());
    dict.insert("RunAtLoad".into(), true.into());
    dict.insert("KeepAlive".into(), true.into());
    dict.insert("ThrottleInterval".into(), 10i64.into());
    dict.insert("LimitLoadToSessionType".into(), "Aqua".into());
    dict.insert("WorkingDirectory".into(), text(home)?.into());
    dict.insert(
        "StandardOutPath".into(),
        text(&paths.state.join("logs/service.stdout.log"))?.into(),
    );
    dict.insert(
        "StandardErrorPath".into(),
        text(&paths.state.join("logs/service.stderr.log"))?.into(),
    );
    Ok(dict.into())
}

pub fn run(command: ServiceCommand, paths: &Paths, output: &crate::Output) -> Result<()> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is required")?);
    ensure!(home.is_absolute(), "HOME must be absolute");
    let directory = home.join("Library/LaunchAgents");
    let file = directory.join(format!("{LABEL}.plist"));
    let domain = format!("gui/{}", unsafe { libc::geteuid() });
    let target = format!("{domain}/{LABEL}");
    match command {
        ServiceCommand::Install(_) => {
            let executable = fs::canonicalize(std::env::current_exe()?)?;
            ensure!(
                executable
                    .parent()
                    .is_some_and(|p| p.ends_with("Contents/MacOS")),
                "install the signed Seccy.app at its permanent location and run its bundled seccy service install"
            );
            server::private_dir(&paths.state)?;
            server::private_dir(&paths.runtime)?;
            server::private_dir(&paths.state.join("logs"))?;
            for name in ["service.stdout.log", "service.stderr.log"] {
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(paths.state.join("logs").join(name))?;
            }
            fs::create_dir_all(&directory)?;
            let temporary = tempfile::NamedTempFile::new_in(&directory)?;
            definition(&executable, &home, paths)?.to_writer_xml(temporary.as_file())?;
            temporary.as_file().sync_all()?;
            temporary.persist(&file)?;
            if launchctl(&["print", &target])?.status.success() {
                checked(&["bootout", &target])?;
            }
            checked(&["enable", &target])?;
            checked(&["bootstrap", &domain, text(&file)?])?;
            emit(
                output,
                json!({"ok": true, "service": LABEL, "plist": file}),
                "Service installed and started; it will start at login",
            )?;
        }
        ServiceCommand::Uninstall(_) => {
            if launchctl(&["print", &target])?.status.success() {
                checked(&["bootout", &target])?;
            }
            match fs::remove_file(&file) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
            emit(output, json!({"ok": true}), "Service uninstalled")?;
        }
        ServiceCommand::Restart(_) => {
            checked(&["kickstart", "-k", &target])?;
            emit(output, json!({"ok": true}), "Service restarted")?;
        }
        ServiceCommand::Status(_) => {
            let status = launchctl(&["print", &target])?;
            let loaded = status.status.success();
            let details = String::from_utf8_lossy(&status.stdout);
            let running = loaded && details.lines().any(|line| line.trim() == "state = running");
            emit(
                output,
                json!({"ok": true, "installed": file.exists(), "loaded": loaded, "running": running, "details": details}),
                &format!(
                    "Installed: {}; loaded: {loaded}; running: {running}\n{details}",
                    file.exists()
                ),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn launch_agent_uses_absolute_paths_and_no_source_config() {
        let paths = Paths::resolve(Some(Path::new("/Users/test")), |_| None).unwrap();
        let value = definition(
            Path::new("/Applications/Seccy.app/Contents/MacOS/seccy"),
            Path::new("/Users/test"),
            &paths,
        )
        .unwrap();
        let mut xml = Vec::new();
        value.to_writer_xml(&mut xml).unwrap();
        let parsed = plist::Value::from_reader(std::io::Cursor::new(xml)).unwrap();
        let dict = parsed.as_dictionary().unwrap();
        let args = dict["ProgramArguments"].as_array().unwrap();
        assert_eq!(args[1].as_string(), Some("agent"));
        assert_eq!(
            args[3].as_string(),
            Some("/Users/test/.local/state/seccy/agent.sock")
        );
        assert_eq!(dict["KeepAlive"].as_boolean(), Some(true));
        let env = dict["EnvironmentVariables"].as_dictionary().unwrap();
        assert_eq!(
            env["XDG_CONFIG_HOME"].as_string(),
            Some("/Users/test/.config")
        );
        assert!(!env.contains_key("LOG_LEVEL"));
    }
}
