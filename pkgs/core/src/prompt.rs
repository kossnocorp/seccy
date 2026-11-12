//! Shared natural-language text for native authorization dialogs.
use crate::{Caller, Mode, ProcessInfo, payload::Payload};
use std::path::Path;

pub(crate) fn value(text: &str) -> String {
    let mut escaped = String::new();
    for ch in text.chars().take(160) {
        if ch.is_control() || matches!(ch, '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            escaped.extend(ch.escape_default());
        } else {
            escaped.push(ch);
        }
    }
    if text.chars().count() > 160 {
        escaped.push('…');
    }
    escaped
}

impl Caller {
    pub fn managed_secrets_description(&self, names: &[&str], keys: &[&str]) -> String {
        let names = names
            .iter()
            .map(|name| value(name))
            .collect::<Vec<_>>()
            .join(", ");
        self.request(
            &format!("Decrypt secrets {names}?"),
            &keys.join(", "),
            &format!("to decrypt secrets {names}"),
            Mode::Prompt,
        )
    }

    pub fn summary(&self) -> String {
        let processes = || self.process.iter().chain(&self.ancestors);
        let chain: Vec<_> = processes().collect();
        let mut labels = Vec::new();
        for (index, process) in chain.iter().enumerate().rev() {
            let label = process_label(process);
            if label == "gnome-shell" && index > 0 {
                continue;
            }
            // Only simplify the observed Git LFS pre-push wrapper.
            if process.name == "pre-push"
                && index > 0
                && process_label(chain[index - 1]) == "Git LFS"
                && chain
                    .get(index + 1)
                    .is_some_and(|p| process_label(p) == "git push")
            {
                continue;
            }
            if matches!(label.as_str(), "VS Code" | "Git LFS") && labels.last() == Some(&label) {
                continue;
            }
            labels.push(label);
        }
        if self.process.is_none() {
            labels.push(value(basename(&self.executable)));
        }
        let mut text = format!("The process chain {}", labels.join(" → "));
        if let Some(repo) = processes().find_map(|p| p.details.repository_candidate.as_ref()) {
            text.push_str(&format!(" running at {}", directory(repo)));
        } else if let Some(cwd) = self
            .process
            .as_ref()
            .and_then(|p| p.details.working_directory.as_ref())
        {
            text.push_str(&format!(" running at {}", directory(cwd)));
        }
        text
    }

    fn git_operation(&self, allowed: &[&str]) -> Option<String> {
        self.process.iter().chain(&self.ancestors).find_map(|p| {
            let command = p.details.command.as_ref()?;
            let subcommand = command.subcommand.as_deref()?;
            (command.tool == "git" && allowed.contains(&subcommand))
                .then(|| format!("git {subcommand}"))
        })
    }

    pub(crate) fn request(&self, heading: &str, key: &str, purpose: &str, mode: Mode) -> String {
        let action = match mode {
            Mode::Prompt => "wants to use",
            Mode::Notify => "used",
        };
        format!(
            "{heading}\n\n{} {action} the {} key {purpose}.",
            self.summary(),
            value(key)
        )
    }
}

impl Payload {
    pub(crate) fn prompt(&self, key: &str, caller: &Caller, mode: Mode) -> String {
        let (heading, purpose) = match self {
            Self::Unknown => (
                "Approve this signing request?".into(),
                "to sign data whose purpose could not be identified".into(),
            ),
            Self::SshSignature { namespace, .. } => {
                let operation = (namespace == "git")
                    .then(|| caller.git_operation(&["commit", "tag"]))
                    .flatten();
                let purpose = match operation.as_deref() {
                    Some("git commit") => "to sign a Git commit".into(),
                    Some("git tag") => "to sign a Git tag".into(),
                    _ if namespace == "git" => "to sign Git data".into(),
                    _ => format!(
                        "to create an SSH signature in the {} namespace",
                        value(namespace)
                    ),
                };
                let heading = operation.map_or_else(
                    || "Approve this signing request?".into(),
                    |operation| format!("Approve the {operation}?"),
                );
                (heading, purpose)
            }
            Self::SshAuthentication { username, .. } => {
                let command = caller
                    .process
                    .as_ref()
                    .and_then(|p| p.details.command.as_ref())
                    .filter(|c| c.tool == "ssh");
                let destination = command.and_then(|c| c.destination_argument.as_deref());
                let heading = caller
                    .git_operation(&["push", "pull", "fetch", "clone", "ls-remote"])
                    .map_or_else(
                        || "Approve this SSH authentication?".into(),
                        |operation| format!("Approve the {operation}?"),
                    );
                let mut text;
                if let Some(destination) = destination {
                    let host = destination
                        .rsplit_once('@')
                        .map_or(destination, |(_, host)| host);
                    text = format!("to access {}@{}", value(username), value(host));
                    if let Some(port) = command.and_then(|c| c.port_argument.as_deref()) {
                        text.push_str(&format!(" (port {})", value(port)));
                    }
                } else {
                    text = format!("to authenticate over SSH as {}", value(username));
                }
                (heading, text)
            }
        };
        let heading = match mode {
            Mode::Prompt => heading.as_str(),
            Mode::Notify => match self {
                Self::SshAuthentication { .. } => "SSH authentication request signed.",
                _ => "Data signed.",
            },
        };
        let mut text = caller.request(heading, key, &purpose, mode);
        let status = self.summary();
        if !status.is_empty() {
            text.push('\n');
            text.push_str(&status);
        }
        text
    }

    pub fn summary(&self) -> String {
        let mut text = String::new();
        if let Self::SshAuthentication { host, .. } = self {
            if let Some(host) = host {
                if host.known_hosts.iter().any(|h| h.revoked) {
                    text.push_str("\n[REVOKED] Server key matches a revoked known_hosts entry");
                }
                if host.known_hosts.is_empty() {
                    text.push_str("\nNo matching key in searched known_hosts files");
                }
            } else {
                text.push_str("\nNo server host key included");
            }
        }
        text
    }
}

fn basename(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}

fn process_label(process: &ProcessInfo) -> String {
    let name = process
        .executable
        .as_deref()
        .map(basename)
        .unwrap_or(&process.name);
    if name == "code" {
        return "VS Code".into();
    }
    if name == "git-lfs" {
        return "Git LFS".into();
    }
    if let Some(command) = &process.details.command
        && command.tool == "git"
        && let Some(subcommand) = &command.subcommand
    {
        return if subcommand == "lfs" {
            "Git LFS".into()
        } else {
            format!("git {}", value(subcommand))
        };
    }
    value(name)
}

fn directory(path: &str) -> String {
    if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty())
        && let Ok(relative) = Path::new(path).strip_prefix(home)
    {
        return value(&if relative.as_os_str().is_empty() {
            "~".into()
        } else {
            format!("~/{}", relative.display())
        });
    }
    value(path)
}
