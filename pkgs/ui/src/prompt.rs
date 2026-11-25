//! The versioned prompt sent to native renderers, independent of window layout.
use crate::copy::{Operation, display, text};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessRef {
    pub pid: i32,
    pub label: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct HostedRepository {
    pub provider: String,
    pub slug: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum Node {
    Text(String),
    Processes(Vec<ProcessRef>),
    Directory(String),
    Repository {
        directory: String,
        origin: HostedRepository,
    },
    Keys(Vec<String>),
    Action(String),
    Secrets(Vec<String>),
}

#[derive(Clone, Debug, Serialize)]
pub struct Prompt {
    pub version: u8,
    pub title: String,
    pub rows: Vec<Vec<Node>>,
}

// Substitute typed slots after Fluent formats the sentence. Never interpret
// caller-provided names or paths as markup, placeholders or Fluent patterns.
fn row(message: &str, slots: &[(&str, Node)]) -> Vec<Node> {
    const MARKERS: [&str; 3] = ["\u{1}", "\u{2}", "\u{3}"];
    let args: Vec<_> = slots
        .iter()
        .zip(MARKERS)
        .map(|((id, _), marker)| (*id, marker))
        .collect();
    let pattern = text(message, &args);
    let mut nodes = Vec::new();
    let mut literal = String::new();
    for c in pattern.chars() {
        if let Some(index) = (c as usize).checked_sub(1).filter(|&i| i < slots.len()) {
            if !literal.is_empty() {
                nodes.push(Node::Text(std::mem::take(&mut literal)));
            }
            nodes.push(slots[index].1.clone());
        } else {
            literal.push(c);
        }
    }
    if !literal.is_empty() {
        nodes.push(Node::Text(literal));
    }
    nodes
}

impl Prompt {
    pub fn new(
        operation: &Operation,
        processes: Vec<ProcessRef>,
        directory: Option<&str>,
        keys: &[String],
    ) -> Self {
        let mut rows = vec![row(
            "prompt-chain",
            &[("chain", Node::Processes(processes))],
        )];
        let mut secrets = Vec::new();
        let (title, action) = match operation {
            Operation::Ssh { username, host, .. } => {
                let user = display(username);
                let target = match host {
                    Some(h) => text(
                        "prompt-ssh-target",
                        &[("user", &user), ("host", &display(h))],
                    ),
                    None => user,
                };
                (
                    "prompt-title-ssh",
                    text("prompt-action-ssh", &[("target", &target)]),
                )
            }
            Operation::GitCommit => ("prompt-title-commit", text("prompt-action-commit", &[])),
            Operation::GitTag => ("prompt-title-tag", text("prompt-action-tag", &[])),
            Operation::GitData => ("prompt-title-git", text("ui-key-action-sign-git", &[])),
            Operation::Signature { namespace } => (
                "prompt-title-sign",
                text(
                    "prompt-action-signature",
                    &[("namespace", &display(namespace))],
                ),
            ),
            Operation::Unknown => ("prompt-title-sign", text("prompt-action-unknown", &[])),
            Operation::Secret { .. } | Operation::Secrets { .. } => {
                secrets = match operation {
                    Operation::Secret { name } => name.iter().cloned().collect(),
                    Operation::Secrets { names } => names.clone(),
                    _ => unreachable!(),
                };
                (
                    if secrets.len() > 1 {
                        "prompt-title-secrets"
                    } else {
                        "request-secret-title"
                    },
                    text(
                        if secrets.is_empty() {
                            "prompt-action-secret"
                        } else {
                            "prompt-action-named"
                        },
                        &[],
                    ),
                )
            }
        };
        let mut distinct = Vec::new();
        for key in keys {
            if !distinct.contains(key) {
                distinct.push(key.clone());
            }
        }
        let mut slots = vec![
            ("keys", Node::Keys(distinct)),
            ("action", Node::Action(action)),
        ];
        let sentence = if secrets.is_empty() {
            "prompt-use"
        } else {
            slots.push(("names", Node::Secrets(secrets)));
            "prompt-decrypt"
        };
        rows.push(row(sentence, &slots));
        if let Some(dir) = directory.filter(|s| !s.is_empty()) {
            rows.push(vec![Node::Directory(dir.to_owned())]);
        }
        Self {
            version: 1,
            title: text(title, &[]),
            rows,
        }
    }

    /// Replace the location's display label without losing its Finder target.
    pub fn with_origin(mut self, origin: Option<HostedRepository>) -> Self {
        if let Some(origin) = origin {
            for node in self.rows.iter_mut().flatten() {
                if let Node::Directory(path) = node {
                    *node = Node::Repository {
                        directory: std::mem::take(path),
                        origin,
                    };
                    break;
                }
            }
        }
        self
    }

    /// Plain text, from the exact same rows as the native renderer.
    pub fn text_preview(&self) -> String {
        let mut lines = vec![self.title.clone()];
        for row in &self.rows {
            lines.push(
                row.iter()
                    .map(|node| match node {
                        Node::Text(s) | Node::Action(s) => s.clone(),
                        Node::Directory(s) => display(s),
                        Node::Repository { directory, origin } => {
                            format!("{} · {}", display(directory), display(&origin.slug))
                        }
                        Node::Keys(names) | Node::Secrets(names) => names
                            .iter()
                            .map(|s| display(s))
                            .collect::<Vec<_>>()
                            .join(", "),
                        Node::Processes(items) => {
                            let mut labels: Vec<_> =
                                items.iter().take(3).map(|p| display(&p.label)).collect();
                            if items.len() > 3 {
                                labels.push("…".into());
                            }
                            labels.join(" ‹ ")
                        }
                    })
                    .collect::<String>(),
            );
        }
        lines.join("\n")
    }
}
