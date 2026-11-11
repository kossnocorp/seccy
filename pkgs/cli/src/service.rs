//! Per-user launchd lifecycle; the agent remains a foreground process.
use crate::{ServiceCommand, emit, server};
use anyhow::{Context, Result, ensure};
use seccy_core::storage::Paths;
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Output as ProcessOutput},
    time::Duration,
};

const LABEL: &str = "fyi.seccy.agent";

fn launchctl(args: &[&str]) -> Result<std::process::Output> {
    Command::new("/bin/launchctl")
        .args(args)
        .output()
        .context("run launchctl")
}

fn check_output(args: &[&str], output: ProcessOutput) -> Result<()> {
    ensure!(
        output.status.success(),
        "launchctl {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn checked(args: &[&str]) -> Result<()> {
    check_output(args, launchctl(args)?)
}

fn write_definition(file: &Path, bytes: &[u8]) -> Result<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(file.parent().context("plist directory")?)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(file)?;
    Ok(())
}

// launchd can still be tearing down a booted-out job when bootstrap returns EIO.
// Retry that error only, with a bound; retain the final launchctl diagnostic.
fn bootstrap(
    domain: &str,
    file: &Path,
    run: &mut impl FnMut(&[&str]) -> Result<ProcessOutput>,
    wait: &mut impl FnMut(),
) -> Result<()> {
    let args = ["bootstrap", domain, text(file)?];
    for attempt in 0..10 {
        let output = run(&args)?;
        if output.status.code() != Some(5) || attempt == 9 {
            return check_output(&args, output);
        }
        wait();
    }
    unreachable!()
}

fn install_definition(
    file: &Path,
    desired: &plist::Value,
    domain: &str,
    target: &str,
    run: &mut impl FnMut(&[&str]) -> Result<ProcessOutput>,
    wait: &mut impl FnMut(),
) -> Result<()> {
    let previous = match fs::read(file) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let unchanged = previous.as_ref().is_some_and(|bytes| {
        plist::Value::from_reader(std::io::Cursor::new(bytes)).is_ok_and(|value| value == *desired)
    });
    let loaded = run(&["print", target])?.status.success();
    check_output(&["enable", target], run(&["enable", target])?)?;
    if loaded && unchanged {
        // Refresh the executable/config without unregistering a working service.
        return check_output(
            &["kickstart", "-k", target],
            run(&["kickstart", "-k", target])?,
        );
    }
    let mut bytes = Vec::new();
    desired.to_writer_xml(&mut bytes)?;
    write_definition(file, &bytes)?;
    let result = (|| {
        if loaded {
            check_output(&["bootout", target], run(&["bootout", target])?)?;
        }
        bootstrap(domain, file, run, wait)
    })();
    if let Err(error) = result {
        if let Some(previous) = previous {
            let rollback = (|| -> Result<()> {
                write_definition(file, &previous)?;
                if loaded && !run(&["print", target])?.status.success() {
                    bootstrap(domain, file, run, wait)?;
                }
                Ok(())
            })();
            return match rollback {
                Ok(()) => Err(error.context("service update failed; previous definition restored")),
                Err(rollback) => Err(error.context(format!(
                    "service update failed; restoring the previous service also failed: {rollback:#}"
                ))),
            };
        }
        return Err(error);
    }
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
            let _install_lock = server::lock(&paths.state.join("service-install.lock"))?;
            install_definition(
                &file,
                &definition(&executable, &home, paths)?,
                &domain,
                &target,
                &mut launchctl,
                &mut || std::thread::sleep(Duration::from_millis(250)),
            )?;
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

    fn sample_definition(program: &str) -> plist::Value {
        let mut dict = plist::Dictionary::new();
        dict.insert("Label".into(), LABEL.into());
        dict.insert("Program".into(), program.into());
        dict.into()
    }

    fn fake_launchctl(
        expected: Vec<(&'static str, i32)>,
    ) -> impl FnMut(&[&str]) -> Result<ProcessOutput> {
        use std::os::unix::process::ExitStatusExt;
        let mut expected = expected.into_iter();
        move |args| {
            let (command, code) = expected.next().expect("unexpected launchctl invocation");
            assert_eq!(args[0], command);
            Ok(ProcessOutput {
                status: std::process::ExitStatus::from_raw(code << 8),
                stdout: Vec::new(),
                stderr: b"simulated launchctl failure".to_vec(),
            })
        }
    }

    #[test]
    fn repeated_install_keeps_job_registered() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("agent.plist");
        let desired = sample_definition("/app/seccy");
        desired.to_file_xml(&file).unwrap();
        let original = fs::read(&file).unwrap();
        for _ in 0..2 {
            let mut calls = Vec::new();
            let mut run = |args: &[&str]| {
                calls.push(args.join(" "));
                use std::os::unix::process::ExitStatusExt;
                Ok(ProcessOutput {
                    status: std::process::ExitStatus::from_raw(0),
                    stdout: vec![],
                    stderr: vec![],
                })
            };
            install_definition(
                &file,
                &desired,
                "gui/501",
                "gui/501/fyi.seccy.agent",
                &mut run,
                &mut || panic!("unexpected retry"),
            )
            .unwrap();
            assert_eq!(
                calls,
                [
                    "print gui/501/fyi.seccy.agent",
                    "enable gui/501/fyi.seccy.agent",
                    "kickstart -k gui/501/fyi.seccy.agent"
                ]
            );
            assert_eq!(fs::read(&file).unwrap(), original);
        }
    }

    #[test]
    fn missing_job_is_bootstrapped_even_with_unchanged_plist() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("agent.plist");
        let desired = sample_definition("/app/seccy");
        desired.to_file_xml(&file).unwrap();
        let mut run = fake_launchctl(vec![("print", 113), ("enable", 0), ("bootstrap", 0)]);
        install_definition(
            &file,
            &desired,
            "gui/501",
            "gui/501/fyi.seccy.agent",
            &mut run,
            &mut || panic!("unexpected retry"),
        )
        .unwrap();
    }

    #[test]
    fn changed_job_retries_transient_bootstrap_failure() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("agent.plist");
        sample_definition("/old/seccy").to_file_xml(&file).unwrap();
        let desired = sample_definition("/new/seccy");
        let mut run = fake_launchctl(vec![
            ("print", 0),
            ("enable", 0),
            ("bootout", 0),
            ("bootstrap", 5),
            ("bootstrap", 0),
        ]);
        let mut waits = 0;
        install_definition(
            &file,
            &desired,
            "gui/501",
            "gui/501/fyi.seccy.agent",
            &mut run,
            &mut || waits += 1,
        )
        .unwrap();
        assert_eq!(waits, 1);
        assert_eq!(plist::Value::from_file(&file).unwrap(), desired);
    }

    #[test]
    fn exhausted_reload_restores_previous_service() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("agent.plist");
        let previous = sample_definition("/old/seccy");
        previous.to_file_xml(&file).unwrap();
        let mut expected = vec![("print", 0), ("enable", 0), ("bootout", 0)];
        expected.extend(std::iter::repeat_n(("bootstrap", 5), 10));
        expected.extend([("print", 113), ("bootstrap", 0)]);
        let mut run = fake_launchctl(expected);
        let mut waits = 0;
        let error = install_definition(
            &file,
            &sample_definition("/new/seccy"),
            "gui/501",
            "gui/501/fyi.seccy.agent",
            &mut run,
            &mut || waits += 1,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("previous definition restored"));
        assert_eq!(waits, 9);
        assert_eq!(plist::Value::from_file(&file).unwrap(), previous);
    }
}
