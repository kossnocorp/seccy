use anyhow::{Context, Result, ensure};
use seccy_core::{Config, Github, storage::Paths};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{io::Write, path::Path, process::Command};

#[derive(Debug)]
pub struct CommandFailed;

impl std::fmt::Display for CommandFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("gh command failed")
    }
}
impl std::error::Error for CommandFailed {}

struct Client(Vec<String>);

impl Client {
    fn new(cmd: &str) -> Result<Self> {
        let words = shell_words::split(cmd).context("invalid --cmd quoting")?;
        ensure!(!words.is_empty(), "--cmd must not be empty");
        Ok(Self(words))
    }

    fn call(&self, args: &[&str]) -> Result<Vec<u8>> {
        let output = Command::new(&self.0[0])
            .args(&self.0[1..])
            .args(args)
            .output()
            .context("execute gh command")?;
        if !output.status.success() {
            std::io::stdout().write_all(&output.stdout)?;
            std::io::stderr().write_all(&output.stderr)?;
            return Err(CommandFailed.into());
        }
        Ok(output.stdout)
    }

    fn list(&self, kind: Github) -> Result<Vec<Key>> {
        let bytes = self.call(&[
            "api",
            endpoint(kind),
            "--paginate",
            "--jq",
            ".[] | {id, title, key}",
        ])?;
        serde_json::Deserializer::from_slice(&bytes)
            .into_iter::<Remote>()
            .map(|remote| {
                let remote = remote.context("invalid gh key list")?;
                Ok(Key {
                    kind,
                    title: remote.title,
                    key: remote.key,
                    id: Some(remote.id),
                })
            })
            .collect()
    }
}

fn endpoint(kind: Github) -> &'static str {
    match kind {
        Github::Auth => "user/keys",
        Github::Signing => "user/ssh_signing_keys",
    }
}

fn kind_name(kind: Github) -> &'static str {
    match kind {
        Github::Auth => "auth",
        Github::Signing => "signing",
    }
}

#[derive(Deserialize)]
struct Remote {
    id: u64,
    title: String,
    key: String,
}

#[derive(Clone, Debug, Serialize)]
struct Key {
    kind: Github,
    title: String,
    key: String,
    id: Option<u64>,
}

#[derive(Default, Debug, Serialize)]
struct Plan {
    remove: Vec<Key>,
    add: Vec<Key>,
}

fn public_material(key: &str) -> Vec<&str> {
    key.split_whitespace().take(2).collect()
}

fn plan(prefix: &str, desired: Vec<Key>, remote: Vec<Key>) -> Plan {
    let mut plan = Plan {
        add: desired,
        ..Plan::default()
    };
    for key in remote {
        let Some(name) = key.title.strip_prefix(prefix) else {
            continue;
        };
        if name.is_empty() || name.contains('/') {
            continue;
        }
        if let Some(index) = plan.add.iter().position(|wanted| {
            wanted.title == key.title
                && wanted.kind == key.kind
                && public_material(&wanted.key) == public_material(&key.key)
        }) {
            plan.add.remove(index);
        } else {
            plan.remove.push(key);
        }
    }
    plan
}

fn machine_prefix() -> Result<String> {
    fn value(program: &str) -> Result<String> {
        let output = Command::new(program).output()?;
        ensure!(output.status.success(), "{program} failed");
        let value = String::from_utf8(output.stdout)?.trim().to_owned();
        ensure!(!value.is_empty(), "{program} returned an empty value");
        Ok(value)
    }
    Ok(format!(
        "{}@{}/seccy/",
        value("/usr/bin/whoami")?,
        value("/bin/hostname")?
    ))
}

pub fn run(
    args: crate::GhSyncArgs,
    config: &Config,
    source: &Path,
    paths: &Paths,
    output: &crate::Output,
) -> Result<()> {
    let client = Client::new(&args.cmd)?;
    let prefix = machine_prefix()?;
    let _lock = crate::inventory::read_lock(paths)?;
    let state = crate::inventory::view(paths, config, source)?;
    let mut desired = Vec::new();
    for (name, record) in &state.keys {
        let kind = config
            .keys
            .get(name)
            .map_or(record.github, |key| key.github);
        let Some(kind) = kind else { continue };
        let identity = state
            .identity(&seccy_macos::SecureEnclave, name)?
            .with_context(|| {
                format!("GitHub key {name} is not provisioned; run seccy provision first")
            })?;
        desired.push(Key {
            kind,
            title: format!("{prefix}{name}"),
            key: identity.public_key,
            id: None,
        });
    }
    let mut remote = client.list(Github::Auth)?;
    remote.extend(client.list(Github::Signing)?);
    let plan = plan(&prefix, desired, remote);
    for key in &plan.remove {
        eprintln!(
            "Remove {} key {:?} (ID {})",
            kind_name(key.kind),
            key.title,
            key.id.unwrap()
        );
    }
    for key in &plan.add {
        eprintln!(
            "Add {} key {:?}: {}",
            kind_name(key.kind),
            key.title,
            key.key
        );
    }
    if !plan.remove.is_empty() || !plan.add.is_empty() {
        crate::inventory::confirm(args.yes, "Apply GitHub key changes?")?;
        for key in &plan.remove {
            client.call(&[
                "api",
                &format!("{}/{}", endpoint(key.kind), key.id.unwrap()),
                "--method",
                "DELETE",
                "--jq",
                ".",
            ])?;
        }
        for key in &plan.add {
            client.call(&[
                "api",
                endpoint(key.kind),
                "--method",
                "POST",
                "--raw-field",
                &format!("title={}", key.title),
                "--raw-field",
                &format!("key={}", key.key),
                "--jq",
                ".",
            ])?;
        }
    }
    crate::emit(
        output,
        json!({"ok": true, "plan": plan}),
        "GitHub keys are synced",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(title: &str, kind: Github, material: &str, id: Option<u64>) -> Key {
        Key {
            title: title.into(),
            kind,
            key: material.into(),
            id,
        }
    }

    #[test]
    fn reconcile_rotation_duplicates_types_and_machine_scope() {
        let prefix = "me@host/seccy/";
        let desired = vec![
            key(
                "me@host/seccy/keep",
                Github::Auth,
                "ssh-type AAA new-comment",
                None,
            ),
            key(
                "me@host/seccy/rotate",
                Github::Signing,
                "ssh-type NEW",
                None,
            ),
            key("me@host/seccy/type", Github::Signing, "ssh-type BBB", None),
        ];
        let remote = vec![
            key(
                "me@host/seccy/keep",
                Github::Auth,
                "ssh-type AAA old-comment",
                Some(1),
            ),
            key("me@host/seccy/keep", Github::Auth, "ssh-type AAA", Some(2)),
            key(
                "me@host/seccy/rotate",
                Github::Signing,
                "ssh-type OLD",
                Some(3),
            ),
            key("me@host/seccy/type", Github::Auth, "ssh-type BBB", Some(4)),
            key(
                "me@host/seccy/stale",
                Github::Signing,
                "ssh-type CCC",
                Some(5),
            ),
            key(
                "me@other/seccy/stale",
                Github::Auth,
                "ssh-type CCC",
                Some(6),
            ),
            key("unmanaged", Github::Auth, "ssh-type CCC", Some(7)),
        ];
        let plan = plan(prefix, desired, remote);
        assert_eq!(
            plan.remove
                .iter()
                .map(|k| k.id.unwrap())
                .collect::<Vec<_>>(),
            [2, 3, 4, 5]
        );
        assert_eq!(plan.add.len(), 2);
    }
}
