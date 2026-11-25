//! Session-local integration. The existing key inventory is read, never provisioned.
use anyhow::{Context, Result, ensure};
use seccy_core::{state::State, storage::Paths};
use std::{
    env, fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
};

use crate::ShellArgs;

mod setup;
use setup::prepare;

const SUPERVISOR: &str = include_str!("shell-session.sh");

pub fn run(args: &ShellArgs) -> Result<()> {
    let capture = if let Some(path) = &args.capture {
        ensure!(
            cfg!(target_os = "macos"),
            "request capture currently requires macOS"
        );
        let path = std::path::absolute(path)?;
        crate::server::private_dir(&path)?;
        Some(path.canonicalize()?)
    } else {
        None
    };
    let paths = Paths::from_env()?;
    let identity = {
        let _lock = crate::inventory::read_lock(&paths)?;
        State::load(&paths)?
            .identity(&crate::platform::Store, &args.name)?
            .context("key is not provisioned; run seccy provision first")?
    };
    let executable = env::current_exe()?.canonicalize()?;
    let shell = args
        .shell
        .clone()
        .or_else(|| env::var_os("SHELL").map(PathBuf::from))
        .context("SHELL is unset; pass --shell /path/to/shell")?;
    let kind = shell.file_name().and_then(|s| s.to_str()).unwrap_or("");
    ensure!(
        matches!(kind, "bash" | "zsh" | "fish"),
        "supported shells: bash, zsh, fish"
    );
    let temporary = tempfile::Builder::new().prefix("sc-").tempdir()?;
    let directory = temporary.path();
    prepare(directory, &executable, &identity.public_key, kind, |name| {
        env::var(name).ok()
    })?;
    eprintln!(
        "Seccy shell: key {}; temporary agent; exit to stop.\nSession files and agent log: {}",
        args.name,
        directory.display()
    );
    // Replace the launcher so signals go to the supervisor, not an extra Rust
    // parent. On exec failure the TempDir still removes all staged files.
    let mut supervisor = Command::new("/bin/bash");
    if let Some(path) = capture {
        eprintln!("Request captures: {}", path.display());
        supervisor.env("SECCY_CAPTURE_DIR", path);
    }
    let error = supervisor
        .args(["-c", SUPERVISOR, "seccy-shell"])
        .arg(directory)
        .arg(&executable)
        .arg(&shell)
        .arg(kind)
        .arg(args.command.as_deref().unwrap_or(""))
        .arg(if args.command.is_some() {
            "command"
        } else {
            "interactive"
        })
        .exec();
    Err(error).context("launch shell supervisor")
}

fn text(path: &Path) -> Result<&str> {
    path.to_str().context("session paths must be UTF-8")
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn executable_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::process::Stdio;

    fn exercise(shell: &str, interactive: bool) {
        if !Path::new(shell).exists() {
            return;
        }
        let fixture = tempfile::tempdir().unwrap();
        let session = tempfile::Builder::new().prefix("sc-").tempdir().unwrap();
        let directory = session.path().to_owned();
        let fake = fixture.path().join("agent");
        executable_file(&fake, "#!/bin/bash\nprintf '%s' \"$$\" > \"$PID_RECORD\"\ntrap 'exit 0' TERM\nprintf '%s\\n' '{\"event\":\"ready\"}'\nwhile :; do sleep 0.1; done\n").unwrap();
        let kind = Path::new(shell).file_name().unwrap().to_str().unwrap();
        let home = fixture.path().to_str().unwrap();
        // Inherit an unrelated env-config entry and an obsolete signing format.
        prepare(
            &directory,
            &fake,
            "ssh-ed25519 AAAATEST fixture",
            kind,
            |name| match name {
                "HOME" => Some(home.into()),
                "GIT_CONFIG_COUNT" => Some("2".into()),
                "GIT_CONFIG_KEY_0" => Some("test.inherited".into()),
                "GIT_CONFIG_VALUE_0" => Some("preserved".into()),
                "GIT_CONFIG_KEY_1" => Some("gpg.format".into()),
                "GIT_CONFIG_VALUE_1" => Some("openpgp".into()),
                _ => None,
            },
        )
        .unwrap();
        let config =
            "[user]\nname = Original User\nemail = original@example.com\n[gpg]\nformat = openpgp\n";
        fs::write(fixture.path().join(".gitconfig"), config).unwrap();
        fs::write(
            fixture.path().join(".bashrc"),
            "printf 'startup-loaded\\n'\nexport SSH_AUTH_SOCK=/wrong\nexport GIT_CONFIG_COUNT=0\n",
        )
        .unwrap();
        fs::write(
            fixture.path().join(".zshrc"),
            "printf 'startup-loaded\\n'\nexport SSH_AUTH_SOCK=/wrong\nexport GIT_CONFIG_COUNT=0\n",
        )
        .unwrap();
        fs::create_dir_all(fixture.path().join(".config/fish")).unwrap();
        fs::write(
            fixture.path().join(".config/fish/config.fish"),
            "printf 'startup-loaded\\n'\nset -gx SSH_AUTH_SOCK /wrong\nset -gx GIT_CONFIG_COUNT 0\n",
        )
        .unwrap();
        let command = "git config user.name; git config test.inherited; git config gpg.format; git config commit.gpgSign; git config user.signingKey; printf '%s\\n' \"$SSH_AUTH_SOCK\"; ssh -G -F /dev/null example.test; exit 7";
        let mut supervisor = Command::new("/bin/bash");
        supervisor
            .args(["-c", SUPERVISOR, "seccy-shell"])
            .arg(&directory)
            .arg(&fake)
            .arg(shell)
            .arg(kind)
            .arg(if interactive { "" } else { command })
            .arg(if interactive {
                "interactive"
            } else {
                "command"
            })
            .env("HOME", fixture.path())
            .env("XDG_CONFIG_HOME", fixture.path().join(".config"))
            .env("GIT_CONFIG_GLOBAL", fixture.path().join(".gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("ZDOTDIR")
            .env("SSH_AUTH_SOCK", "/original")
            .env("PID_RECORD", fixture.path().join("pid"))
            .current_dir(fixture.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = if interactive {
            // A real controlling terminal catches job-control failures that a
            // pipe-only interactive test would miss.
            let (mut master, mut slave) = (0, 0);
            assert_eq!(
                unsafe {
                    libc::openpty(
                        &mut master,
                        &mut slave,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            let mut master = unsafe { fs::File::from_raw_fd(master) };
            let slave = unsafe { fs::File::from_raw_fd(slave) };
            unsafe {
                libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
                libc::fcntl(slave.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
                supervisor.pre_exec(|| {
                    if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            supervisor
                .stdin(slave.try_clone().unwrap())
                .stdout(slave.try_clone().unwrap())
                .stderr(slave.try_clone().unwrap())
                .env("TERM", "dumb");
            let mut child = supervisor.spawn().unwrap();
            drop(supervisor);
            drop(slave);
            writeln!(master, "{command}").unwrap();
            let reader = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let _ = master.read_to_end(&mut bytes); // PTYs can finish with EIO.
                bytes
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    panic!("interactive shell did not exit: {shell}");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            };
            std::process::Output {
                status,
                stdout: reader.join().unwrap(),
                stderr: Vec::new(),
            }
        } else {
            supervisor.output().unwrap()
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(7), "{shell}: {stdout}\n{stderr}");
        if interactive {
            assert_eq!(stdout.matches("startup-loaded").count(), 1, "{stderr}");
        }
        for expected in [
            "Original User",
            "preserved",
            "ssh",
            "true",
            directory.to_str().unwrap(),
        ] {
            assert!(
                stdout.contains(expected),
                "{shell}: missing {expected}: {stdout}\n{stderr}"
            );
        }
        assert!(
            stdout.contains(&format!(
                "identityagent {}/seccy/agent.sock",
                directory.display()
            )),
            "{stdout}"
        );
        assert!(!stdout.contains("/wrong"), "{stdout}");
        assert!(!directory.exists(), "session files must be removed");
        assert_eq!(
            fs::read_to_string(fixture.path().join(".gitconfig")).unwrap(),
            config
        );
        let pid: i32 = fs::read_to_string(fixture.path().join("pid"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "agent must be reaped");
    }

    #[test]
    fn bash_session_preserves_config_and_cleans_up_on_nonzero_exit() {
        exercise("/bin/bash", false);
        exercise("/bin/bash", true);
    }

    #[test]
    fn zsh_and_fish_apply_overrides_after_startup() {
        for shell in ["/bin/zsh", "/opt/homebrew/bin/fish", "/usr/bin/fish"] {
            exercise(shell, false);
            exercise(shell, true);
        }
    }

    #[test]
    fn supervisor_cleans_up_on_startup_failure_and_termination() {
        for fail_startup in [true, false] {
            let fixture = tempfile::tempdir().unwrap();
            let session = tempfile::Builder::new().prefix("sc-").tempdir().unwrap();
            let directory = session.path().to_owned();
            let fake = fixture.path().join("agent");
            executable_file(&fake, if fail_startup {
                "#!/bin/sh\necho 'fixture startup failure' >&2\nexit 42\n"
            } else {
                "#!/bin/sh\necho $$ > \"$PID_RECORD\"\ntrap 'exit 0' TERM\necho '{\"event\":\"ready\"}'\nwhile :; do sleep 0.1; done\n"
            }).unwrap();
            prepare(
                &directory,
                &fake,
                "ssh-ed25519 AAAATEST fixture",
                "bash",
                |name| (name == "HOME").then(|| fixture.path().to_str().unwrap().into()),
            )
            .unwrap();
            let child_pid_file = fixture.path().join("child");
            let mut supervisor = Command::new("/bin/bash")
                .args(["-c", SUPERVISOR, "seccy-shell"])
                .arg(&directory)
                .arg(&fake)
                .args(["/bin/bash", "bash"])
                .arg(format!(
                    "echo $$ > {}; exec sleep 60",
                    quote(text(&child_pid_file).unwrap())
                ))
                .arg("command")
                .env("PID_RECORD", fixture.path().join("agent-pid"))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            if !fail_startup {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !child_pid_file.exists() {
                    assert!(std::time::Instant::now() < deadline, "shell did not start");
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                assert_eq!(
                    unsafe { libc::kill(supervisor.id() as i32, libc::SIGTERM) },
                    0
                );
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
            while supervisor.try_wait().unwrap().is_none() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "supervisor did not stop"
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let output = supervisor.wait_with_output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(if fail_startup { 1 } else { 143 })
            );
            assert!(!directory.exists());
            if fail_startup {
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("fixture startup failure")
                );
                assert!(!child_pid_file.exists());
            } else {
                for path in [child_pid_file, fixture.path().join("agent-pid")] {
                    let pid: i32 = fs::read_to_string(path).unwrap().trim().parse().unwrap();
                    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
                }
            }
        }
    }
}
