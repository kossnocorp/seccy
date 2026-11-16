//! Fluent-backed copy shared by native UIs. No platform or key-store dependencies.
use fluent_bundle::{FluentArgs, FluentBundle, FluentResource};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const ENGLISH: &str = include_str!("../locales/en-US/seccy.ftl");

thread_local! {
    static BUNDLE: FluentBundle<FluentResource> = {
        let mut bundle = FluentBundle::new(vec!["en-US".parse().unwrap()]);
        bundle.add_resource(FluentResource::try_new(ENGLISH.to_owned()).expect("valid Fluent catalog"))
            .expect("unique Fluent messages");
        // Values are escaped before interpolation. English-only initially; do
        // not emit bidi controls which the native identity sanitizer rejects.
        bundle.set_use_isolating(false);
        bundle
    };
}

/// Format using the bundled English catalog. Locale negotiation is intentionally
/// deferred until a second translation is shipped.
pub fn text(id: &str, values: &[(&str, &str)]) -> String {
    BUNDLE.with(|bundle| {
        let message = bundle
            .get_message(id)
            .unwrap_or_else(|| panic!("missing Fluent message: {id}"));
        let mut args = FluentArgs::new();
        for (name, value) in values {
            args.set(*name, *value);
        }
        let mut errors = vec![];
        let result = bundle
            .format_pattern(
                message.value().expect("message value"),
                Some(&args),
                &mut errors,
            )
            .into_owned();
        assert!(
            errors.is_empty(),
            "Fluent formatting failed for {id}: {errors:?}"
        );
        result
    })
}

/// Bound and escape untrusted identities without interpreting markup.
pub fn display(value: &str) -> String {
    let mut result = String::new();
    for ch in value.chars().take(160) {
        if ch.is_control() || matches!(ch, '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            result.extend(ch.escape_default());
        } else {
            result.push(ch);
        }
    }
    if value.chars().count() > 160 {
        result.push('…');
    }
    result
}

#[derive(Clone, Debug)]
pub enum Operation {
    Unknown,
    GitCommit,
    GitTag,
    GitData,
    Signature {
        namespace: String,
    },
    Ssh {
        username: String,
        host: Option<String>,
        port: Option<String>,
        git_operation: Option<String>,
    },
    Secret {
        name: Option<String>,
    },
    Secrets {
        names: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum Warning {
    Revoked,
    UnknownHost,
    MissingHost,
}

#[derive(Clone, Debug)]
pub struct Activity {
    pub operation: Operation,
    pub key: String,
    /// Display-safe process labels, joined by the caller. No natural-language prefix.
    pub chain: String,
    pub directory: Option<String>,
    pub warnings: Vec<Warning>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Content {
    pub title: String,
    pub body: String,
    pub warning: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    pub title: String,
    pub body: String,
}

impl Activity {
    pub fn content(&self, notify: bool) -> Content {
        let key = display(&self.key);
        let directory = self.directory.as_deref().unwrap_or("");
        let mut args = vec![
            ("key", key.as_str()),
            ("chain", self.chain.as_str()),
            ("directory", directory),
            (
                "location",
                if self.directory.is_some() {
                    "directory"
                } else {
                    "none"
                },
            ),
            ("mode", if notify { "notify" } else { "prompt" }),
        ];
        let (mut title, body) = match &self.operation {
            Operation::Unknown => ("request-sign-title", "request-unknown-body"),
            Operation::GitCommit => {
                args.push(("operation", "git commit"));
                ("request-git-title", "request-commit-body")
            }
            Operation::GitTag => {
                args.push(("operation", "git tag"));
                ("request-git-title", "request-tag-body")
            }
            Operation::GitData => ("request-sign-title", "request-git-body"),
            Operation::Signature { .. } => ("request-sign-title", "request-signature-body"),
            Operation::Ssh {
                host,
                git_operation,
                ..
            } => {
                if let Some(operation) = git_operation {
                    args.push(("operation", operation));
                }
                (
                    if git_operation.is_some() {
                        "request-git-title"
                    } else {
                        "request-ssh-title"
                    },
                    if host.is_some() {
                        "request-ssh-host-body"
                    } else {
                        "request-ssh-body"
                    },
                )
            }
            Operation::Secret { name: Some(_) } => {
                ("request-named-secret-title", "request-named-secret-body")
            }
            Operation::Secret { name: None } => ("request-secret-title", "request-secret-body"),
            Operation::Secrets { .. } => ("request-secrets-title", "request-secrets-body"),
        };
        let mut dynamic = Vec::new();
        match &self.operation {
            Operation::Signature { namespace } => dynamic.push(("namespace", display(namespace))),
            Operation::Ssh {
                username,
                host,
                port,
                ..
            } => {
                dynamic.push(("username", display(username)));
                dynamic.push(("host", display(host.as_deref().unwrap_or(""))));
                dynamic.push(("port", display(port.as_deref().unwrap_or(""))));
                args.push(("port-present", if port.is_some() { "yes" } else { "no" }));
            }
            Operation::Secret { name: Some(name) } => dynamic.push(("names", display(name))),
            Operation::Secrets { names } => dynamic.push((
                "names",
                names
                    .iter()
                    .map(|s| display(s))
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
            _ => {}
        }
        args.extend(dynamic.iter().map(|(key, value)| (*key, value.as_str())));
        if notify {
            title = match &self.operation {
                Operation::Ssh { .. } => "notification-ssh-title",
                Operation::Secret { name: Some(_) } => "notification-named-secret-title",
                Operation::Secret { name: None } => "notification-secret-title",
                Operation::Secrets { .. } => "notification-secrets-title",
                _ => "notification-sign-title",
            };
        }
        let mut body = text(body, &args);
        for warning in &self.warnings {
            body.push_str("\n\n");
            body.push_str(&text(
                match warning {
                    Warning::Revoked => "warning-revoked",
                    Warning::UnknownHost => "warning-unknown-host",
                    Warning::MissingHost => "warning-missing-host",
                },
                &[],
            ));
        }
        Content {
            title: text(title, &args),
            body,
            warning: !self.warnings.is_empty(),
        }
    }
    pub fn notification(&self) -> Notification {
        let content = self.content(true);
        Notification {
            title: text(
                if matches!(
                    self.operation,
                    Operation::Secret { .. } | Operation::Secrets { .. }
                ) {
                    "notification-secret"
                } else {
                    "notification-key"
                },
                &[],
            ),
            body: format!("{}\n\n{}", content.title, content.body),
        }
    }
}

/// Build-time adapter for the standalone Swift gallery and static UI labels.
/// Production request content is formatted directly in Rust at runtime.
pub fn swift_source() -> String {
    let labels: BTreeMap<_, _> = ENGLISH
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .filter(|(id, _)| {
            id.starts_with("ui-")
                || id.starts_with("notification-error-")
                || id.starts_with("gallery-")
        })
        .filter(|(id, _)| *id != "ui-pid")
        .map(|(id, _)| (id, text(id, &[])))
        .collect();
    let mut fixtures = BTreeMap::new();
    for (id, operation, chain, key, executable, pid, warnings) in [
        (
            "signing",
            Operation::GitCommit,
            "Terminal → zsh → git commit".into(),
            "work",
            "/usr/bin/git",
            4217,
            vec![],
        ),
        (
            "secrets",
            Operation::Secrets {
                names: vec!["GITHUB_TOKEN".into(), "DATABASE_URL".into()],
            },
            "Terminal → fnox".into(),
            "work",
            "/opt/homebrew/bin/fnox",
            4218,
            vec![],
        ),
        (
            "revoked",
            Operation::Ssh {
                username: "git".into(),
                host: Some("example.com".into()),
                port: None,
                git_operation: Some("git push".into()),
            },
            "Terminal → git push → ssh".into(),
            "work",
            "/usr/bin/ssh",
            4219,
            vec![Warning::Revoked],
        ),
        (
            "long",
            Operation::Unknown,
            "Terminal → very-long-process-name → ".repeat(24),
            "work_🔐_e\u{301}",
            "/tmp/untrusted/**not bold**/\u{202e}process",
            4220,
            vec![],
        ),
    ] {
        let activity = Activity {
            operation,
            key: key.into(),
            chain,
            directory: None,
            warnings,
        };
        fixtures.insert(
            id,
            serde_json::json!({
                "content": activity.content(false), "notification": activity.notification(),
                "key": key, "executable": executable, "pid": pid,
                "pidLabel": text("ui-pid", &[("pid", &pid.to_string())]),
                "processes": [
                    {
                        "pid": pid,
                        "pidLabel": text("ui-pid", &[("pid", &pid.to_string())]),
                        "name": executable.rsplit('/').next().unwrap_or(executable),
                        "executable": executable,
                        "startSeconds": 0, "startMicroseconds": 0, "bundlePaths": []
                    },
                    {
                        "pid": 4100,
                        "pidLabel": text("ui-pid", &[("pid", "4100")]),
                        "name": "zsh", "executable": "/bin/zsh",
                        "startSeconds": 0, "startMicroseconds": 0, "bundlePaths": []
                    },
                    {
                        "pid": 4000,
                        "pidLabel": text("ui-pid", &[("pid", "4000")]),
                        "name": "Terminal",
                        "executable": "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                        "startSeconds": 0, "startMicroseconds": 0,
                        "bundlePaths": ["/System/Applications/Utilities/Terminal.app"]
                    }
                ],
                "fingerprint": "SHA256:KvdQ3vU2Tji0YtGYnGQeG79n6Cj4n94JUu6cN0aR1wk"
            }),
        );
    }
    let json =
        serde_json::to_string_pretty(&serde_json::json!({"labels": labels, "fixtures": fixtures}))
            .unwrap();
    format!(
        "// Generated by seccy_copy from Fluent. Do not edit.\nlet sharedCopyJSON = #\"\"\"\n{json}\n\"\"\"#\n"
    )
}
