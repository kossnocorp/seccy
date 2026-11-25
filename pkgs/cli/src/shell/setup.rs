//! Generate session-local wrappers and shell startup files.
use super::{executable_file, quote, text};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

pub(super) fn prepare(
    directory: &Path,
    executable: &Path,
    public_key: &str,
    kind: &str,
    get: impl Fn(&str) -> Option<String>,
) -> Result<()> {
    let bin = directory.join("bin");
    fs::create_dir(&bin)?;
    let runtime = directory.join("seccy");
    crate::server::private_dir(&runtime)?;
    let socket = runtime.join("agent.sock");
    // sockaddr_un.sun_path is only 104 bytes on Darwin (108 on Linux).
    ensure!(
        text(&socket)?.len() < 104,
        "temporary socket path is too long; use a shorter TMPDIR"
    );
    let key = directory.join("key.pub");
    fs::write(&key, format!("{public_key}\n"))?;
    std::os::unix::fs::symlink(executable, bin.join("seccy"))?;
    executable_file(
        &bin.join("ssh"),
        &format!(
            "#!/bin/sh\nexec /usr/bin/ssh -o {} -o IdentitiesOnly=yes -o ControlPath=none -i {} \"$@\"\n",
            quote(&format!(
                "IdentityAgent=\"{}\"",
                text(&socket)?.replace('\\', "\\\\").replace('"', "\\\"")
            )),
            quote(text(&key)?)
        ),
    )?;

    // Keep the normal Git config hierarchy, including repository/conditional
    // config, and append command-scope overrides to any inherited env entries.
    let count = get("GIT_CONFIG_COUNT")
        .unwrap_or_else(|| "0".into())
        .parse::<usize>()
        .context("invalid GIT_CONFIG_COUNT")?;
    ensure!(count <= 4096, "GIT_CONFIG_COUNT is too large");
    let overrides = [
        ("gpg.format", "ssh".to_owned()),
        ("gpg.ssh.program", "/usr/bin/ssh-keygen".into()),
        ("user.signingKey", text(&key)?.into()),
        ("commit.gpgSign", "true".into()),
        ("tag.gpgSign", "true".into()),
    ];
    let mut variables = vec![
        ("SSH_AUTH_SOCK".to_owned(), text(&socket)?.to_owned()),
        ("XDG_RUNTIME_DIR".into(), text(directory)?.into()),
        ("SECCY_SHELL".into(), text(directory)?.into()),
        ("GIT_SSH_COMMAND".into(), quote(text(&bin.join("ssh"))?)),
        ("GIT_SSH_VARIANT".into(), "ssh".into()),
        (
            "GIT_CONFIG_COUNT".into(),
            (count + overrides.len()).to_string(),
        ),
    ];
    for index in 0..count {
        for field in ["KEY", "VALUE"] {
            let name = format!("GIT_CONFIG_{field}_{index}");
            variables.push((
                name.clone(),
                get(&name).with_context(|| format!("missing {name}"))?,
            ));
        }
    }
    for (index, (name, value)) in overrides.into_iter().enumerate() {
        variables.push((format!("GIT_CONFIG_KEY_{}", count + index), name.into()));
        variables.push((format!("GIT_CONFIG_VALUE_{}", count + index), value));
    }
    let home = get("HOME").context("HOME is required")?;
    let init = if kind == "fish" {
        let fish_quote = |s: &str| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"));
        let mut script = String::from("functions --erase ssh seccy\n");
        for (name, value) in &variables {
            script.push_str(&format!("set -gx {name} {}\n", fish_quote(value)));
        }
        script.push_str(&format!("set -gx PATH {} $PATH\n", fish_quote(text(&bin)?)));
        script
    } else {
        let mut script = String::from(
            "unalias ssh seccy 2>/dev/null || true\nunset -f ssh seccy 2>/dev/null || true\n",
        );
        for (name, value) in &variables {
            script.push_str(&format!("export {name}={}\n", quote(value)));
        }
        script.push_str(&format!("export PATH={}:\"$PATH\"\n", quote(text(&bin)?)));
        script
    };
    fs::write(directory.join("apply"), init)?;
    let apply = format!(". {}\n", quote(text(&directory.join("apply"))?));
    fs::write(
        directory.join("bashrc"),
        format!(
            "[ ! -f {0} ] || . {0}\n{apply}",
            quote(&format!("{home}/.bashrc"))
        ),
    )?;
    // zsh reads our .zshenv after /etc/zshenv. Load the user's original file,
    // remember any ZDOTDIR it sets, then route .zshrc through the session.
    let original_zdotdir = get("ZDOTDIR");
    let zdotdir = original_zdotdir.as_deref().unwrap_or(&home);
    let restore_zdotdir = original_zdotdir
        .as_deref()
        .map(|value| format!("export ZDOTDIR={}\n", quote(value)))
        .unwrap_or_else(|| "unset ZDOTDIR\n".into());
    fs::write(
        directory.join(".zshenv"),
        format!(
            "{restore_zdotdir}[ ! -f {0} ] || . {0}\n_SECCY_USER_ZDOTDIR=${{ZDOTDIR-{1}}}\n_SECCY_ZDOTDIR_SET=${{ZDOTDIR+x}}\nexport ZDOTDIR={2}\n",
            quote(&format!("{zdotdir}/.zshenv")),
            quote(zdotdir),
            quote(text(directory)?)
        ),
    )?;
    fs::write(
        directory.join(".zshrc"),
        format!(
            "if [[ $_SECCY_ZDOTDIR_SET == x ]]; then export ZDOTDIR=\"$_SECCY_USER_ZDOTDIR\"; else unset ZDOTDIR; fi\n[ ! -f \"$_SECCY_USER_ZDOTDIR/.zshrc\" ] || . \"$_SECCY_USER_ZDOTDIR/.zshrc\"\nunset _SECCY_USER_ZDOTDIR _SECCY_ZDOTDIR_SET\n{apply}"
        ),
    )?;
    Ok(())
}
