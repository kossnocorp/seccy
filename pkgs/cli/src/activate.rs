use anyhow::{Context, Result, bail, ensure};
use seccy_core::storage::Paths;
use serde_json::json;
use std::{env, path::Path};

use crate::output::Output;

pub fn run(shell: Option<&str>, output: &Output) -> Result<()> {
    let detected = env::var("SHELL").ok();
    let shell = shell
        .or_else(|| {
            detected
                .as_deref()
                .and_then(|s| Path::new(s).file_name()?.to_str())
        })
        .context(
            "Cannot detect shell; pass bash, elvish, fish, nu, xonsh, zsh, pwsh, or powershell",
        )?;
    let bin = match env::var("XDG_BIN_HOME").ok().filter(|s| !s.is_empty()) {
        Some(bin) => {
            ensure!(
                Path::new(&bin).is_absolute(),
                "XDG_BIN_HOME must be absolute"
            );
            bin
        }
        None => {
            let home = env::var("HOME").context("HOME is required when XDG_BIN_HOME is unset")?;
            ensure!(Path::new(&home).is_absolute(), "HOME must be absolute");
            format!("{home}/.local/bin")
        }
    };
    let socket = Paths::from_env()?.runtime.join("agent.sock");
    let socket = socket.to_str().context("Socket path must be UTF-8")?;
    let script = render(shell, &bin, socket)?;
    output.emit(json!({"ok": true, "script": script}), &script)
}

fn render(shell: &str, bin: &str, socket: &str) -> Result<String> {
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let literal = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let fish = |s: &str| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"));
    let double = |s: &str| serde_json::to_string(s).expect("serialize string");
    Ok(match shell {
        "bash" | "zsh" => format!(
            "export PATH={}:\"$PATH\"\nexport SSH_AUTH_SOCK={}\n",
            quote(bin),
            quote(socket)
        ),
        "fish" => format!(
            "set -gx PATH {} $PATH\nset -gx SSH_AUTH_SOCK {}\n",
            fish(bin),
            fish(socket)
        ),
        "elvish" => format!(
            "set paths = [{} $@paths]\nset-env SSH_AUTH_SOCK {}\n",
            literal(bin),
            literal(socket)
        ),
        "nu" => format!(
            "$env.PATH = ($env.PATH | prepend {})\n$env.SSH_AUTH_SOCK = {}\n",
            double(bin),
            double(socket)
        ),
        "xonsh" => format!(
            "$PATH.insert(0, {})\n$SSH_AUTH_SOCK = {}\n",
            double(bin),
            double(socket)
        ),
        "pwsh" | "powershell" => format!(
            "$env:PATH = {} + [IO.Path]::PathSeparator + $env:PATH\n$env:SSH_AUTH_SOCK = {}\n",
            literal(bin),
            literal(socket)
        ),
        _ => bail!(
            "Unsupported shell {shell:?}; expected bash, elvish, fish, nu, xonsh, zsh, pwsh, or powershell"
        ),
    })
}
