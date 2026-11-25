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

#[derive(Clone, Debug, Deserialize)]
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

/// Semantic artwork IDs; never inferred by parsing localized text.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    #[serde(rename = "requestTitle", default)]
    pub request_title: String,
    #[serde(rename = "keyAction", default)]
    pub key_action: String,
    pub title: String,
    pub target: String,
    pub action: String,
    pub permission: Vec<PermissionPart>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionPart {
    pub kind: String,
    pub value: String,
}

pub fn hosting_provider(host: &str) -> &'static str {
    match host.trim_end_matches('.').to_ascii_lowercase().as_str() {
        "github.com" | "ssh.github.com" => "github",
        "gitlab.com" | "altssh.gitlab.com" => "gitlab",
        "bitbucket.org" | "altssh.bitbucket.org" => "bitbucket",
        _ => "git",
    }
}

impl Activity {
    pub fn header(&self, app: &str) -> Header {
        let (operation, target, action) = match &self.operation {
            Operation::GitCommit => (Some("commit"), "git", "commit"),
            Operation::GitTag => (Some("tag"), "git", "sell"),
            Operation::GitData => (Some("sign"), "git", "commit"),
            Operation::Ssh {
                host,
                git_operation: Some(operation),
                ..
            } => {
                let operation = operation.strip_prefix("git ").unwrap_or(operation);
                (
                    Some(operation),
                    hosting_provider(host.as_deref().unwrap_or("")),
                    if operation == "push" {
                        "cloud_upload"
                    } else {
                        "cloud_download"
                    },
                )
            }
            Operation::Secret { .. } | Operation::Secrets { .. } => {
                (None, "data_object", "lock_open")
            }
            _ => (None, "key", "key"),
        };
        // Translate the complete sentence, then substitute semantic runs. Caller
        // values are never parsed for markup or placeholder tokens.
        let sentence = text("header-permission", &[("app", "\u{1}"), ("key", "\u{2}")]);
        let mut permission = Vec::new();
        let mut literal = String::new();
        for ch in sentence.chars() {
            let slot = match ch {
                '\u{1}' => Some(("app", app)),
                '\u{2}' => Some(("key", self.key.as_str())),
                _ => None,
            };
            if let Some((kind, value)) = slot {
                if !literal.is_empty() {
                    permission.push(PermissionPart {
                        kind: "text".into(),
                        value: std::mem::take(&mut literal),
                    });
                }
                permission.push(PermissionPart {
                    kind: kind.into(),
                    value: display(value),
                });
            } else {
                literal.push(ch);
            }
        }
        if !literal.is_empty() {
            permission.push(PermissionPart {
                kind: "text".into(),
                value: literal,
            });
        }
        Header {
            request_title: text(
                "request-popover-title",
                &[(
                    "operation",
                    operation.unwrap_or(match &self.operation {
                        Operation::Secret { .. } | Operation::Secrets { .. } => "decrypt",
                        Operation::Ssh { .. } => "ssh",
                        _ => "signature",
                    }),
                )],
            ),
            key_action: text(
                match self.operation {
                    Operation::Ssh { .. } => "ui-key-action-ssh",
                    Operation::Secret { .. } | Operation::Secrets { .. } => "ui-key-action-decrypt",
                    Operation::GitCommit | Operation::GitTag | Operation::GitData => {
                        "ui-key-action-sign-git"
                    }
                    _ => "ui-key-action-sign",
                },
                &[],
            ),
            title: operation
                .map(|operation| text("header-git-title", &[("operation", operation)]))
                .unwrap_or_else(|| self.content(false).title),
            target: target.into(),
            action: action.into(),
            permission,
        }
    }

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
fn gallery_copy(activity: &Activity) -> serde_json::Value {
    let mut template = activity.clone();
    // A trusted template slot, substituted once with literal display-safe text
    // by Swift. Reformat through Fluent rather than replacing the sample key.
    template.key = "\u{e000}seccy-key\u{e001}".into();
    serde_json::json!({
        "content": template.content(false),
        "notification": template.notification(),
        "header": template.header("Terminal"),
    })
}

fn gallery_prompt(activity: &Activity, fixture: &serde_json::Value) -> crate::prompt::Prompt {
    let refs = fixture["processes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| crate::prompt::ProcessRef {
            pid: p["pid"].as_i64().unwrap() as i32,
            label: p["name"].as_str().unwrap().to_owned(),
        })
        .collect();
    crate::prompt::Prompt::new(
        &activity.operation,
        refs,
        fixture["workingDirectory"].as_str(),
        std::slice::from_ref(&activity.key),
    )
    .with_origin(Some(crate::prompt::HostedRepository {
        provider: "github".into(),
        slug: "kossnocorp/seccy".into(),
    }))
}

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
            "github",
            Operation::Ssh {
                username: "git".into(),
                host: Some("github.com".into()),
                port: None,
                git_operation: Some("git push".into()),
            },
            "Terminal → git push → ssh".into(),
            "work",
            "/usr/bin/ssh",
            4221,
            vec![],
        ),
        (
            "gitlab",
            Operation::Ssh {
                username: "git".into(),
                host: Some("gitlab.com".into()),
                port: None,
                git_operation: Some("git fetch".into()),
            },
            "Terminal → git fetch → ssh".into(),
            "work",
            "/usr/bin/ssh",
            4222,
            vec![],
        ),
        (
            "bitbucket",
            Operation::Ssh {
                username: "git".into(),
                host: Some("bitbucket.org".into()),
                port: None,
                git_operation: Some("git pull".into()),
            },
            "Terminal → git pull → ssh".into(),
            "work",
            "/usr/bin/ssh",
            4223,
            vec![],
        ),
        (
            "generic",
            Operation::Ssh {
                username: "git".into(),
                host: Some("git.company.example".into()),
                port: None,
                git_operation: Some("git fetch".into()),
            },
            "Terminal → git fetch → ssh".into(),
            "work",
            "/usr/bin/ssh",
            4224,
            vec![],
        ),
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
        let mut fixture = serde_json::json!({
            "content": activity.content(false), "notification": activity.notification(),
            "header": activity.header("Terminal"),
            "previewCopy": gallery_copy(&activity),
            "appPid": 4000,
            "diagnostics": serde_json::to_string_pretty(&serde_json::json!({
                "source": "synthetic gallery fixture",
                "peer_pid": pid,
                "executable": executable,
                "signing": if id == "signing" { serde_json::json!({
                    "decoded": {
                        "kind": "ssh_signature", "namespace": "git",
                        "hash_algorithm": "sha512",
                        "digest_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                    }
                }) } else { serde_json::Value::Null }
            })).unwrap(),
            "workingDirectory": "~/code/seccy",
            "key": key, "executable": executable, "pid": pid,
            "pidLabel": text("ui-pid", &[("pid", &pid.to_string())]),
            "processes": [
                {
                    "pid": pid,
                    "pidLabel": text("ui-pid", &[("pid", &pid.to_string())]),
                    "name": executable.rsplit('/').next().unwrap_or(executable),
                    "executable": executable,
                    "diagnostics": serde_json::to_string_pretty(&serde_json::json!({
                        "source": "synthetic gallery fixture",
                        "pid": pid, "parent_pid": 4100, "executable": executable,
                        "details": { "arguments": [executable], "working_directory": "/Users/example/code/seccy" }
                    })).unwrap(),
                    "startSeconds": 0, "startMicroseconds": 0, "bundlePaths": []
                },
                {
                    "pid": 4100,
                    "pidLabel": text("ui-pid", &[("pid", "4100")]),
                    "name": "zsh", "executable": "/bin/zsh",
                    "diagnostics": "{\n  \"source\": \"synthetic gallery fixture\",\n  \"arguments\": [\"/bin/zsh\", \"-l\"]\n}",
                    "startSeconds": 0, "startMicroseconds": 0, "bundlePaths": []
                },
                {
                    "pid": 4000,
                    "pidLabel": text("ui-pid", &[("pid", "4000")]),
                    "name": "Terminal",
                    "diagnostics": "{\n  \"source\": \"synthetic gallery fixture\",\n  \"bundle_identifier\": \"com.apple.Terminal\"\n}",
                    "executable": "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                    "startSeconds": 0, "startMicroseconds": 0,
                    "bundlePaths": ["/System/Applications/Utilities/Terminal.app"]
                }
            ],
            "fingerprint": "SHA256:KvdQ3vU2Tji0YtGYnGQeG79n6Cj4n94JUu6cN0aR1wk"
        });
        fixture["presentation"] =
            serde_json::to_value(gallery_prompt(&activity, &fixture)).unwrap();
        fixtures.insert(id.to_owned(), fixture);
    }
    // Generate each action/provider combination through the production presenter
    // so the header, destination, details and notification always agree.
    for action in ["push", "pull", "fetch", "clone", "ls-remote"] {
        for (provider, host) in [
            ("github", "github.com"),
            ("gitlab", "gitlab.com"),
            ("bitbucket", "bitbucket.org"),
            ("generic", "git.company.example"),
        ] {
            let activity = Activity {
                operation: Operation::Ssh {
                    username: "git".into(),
                    host: Some(host.into()),
                    port: None,
                    git_operation: Some(format!("git {action}")),
                },
                key: "work".into(),
                chain: format!("Terminal → zsh → git {action} → ssh"),
                directory: None,
                warnings: vec![],
            };
            let mut fixture = fixtures["github"].clone();
            fixture["content"] = serde_json::to_value(activity.content(false)).unwrap();
            fixture["notification"] = serde_json::to_value(activity.notification()).unwrap();
            fixture["header"] = serde_json::to_value(activity.header("Terminal")).unwrap();
            fixture["previewCopy"] = gallery_copy(&activity);
            fixture["presentation"] =
                serde_json::to_value(gallery_prompt(&activity, &fixture)).unwrap();
            fixtures.insert(format!("{action}-{provider}"), fixture);
        }
    }
    let tag = Activity {
        operation: Operation::GitTag,
        key: "work".into(),
        chain: "Terminal → zsh → git tag".into(),
        directory: None,
        warnings: vec![],
    };
    let mut fixture = fixtures["signing"].clone();
    fixture["content"] = serde_json::to_value(tag.content(false)).unwrap();
    fixture["notification"] = serde_json::to_value(tag.notification()).unwrap();
    fixture["header"] = serde_json::to_value(tag.header("Terminal")).unwrap();
    fixture["previewCopy"] = gallery_copy(&tag);
    fixture["presentation"] = serde_json::to_value(gallery_prompt(&tag, &fixture)).unwrap();
    fixtures.insert("tag".into(), fixture);
    // Embed the vdm-pinned SVGs so the static library needs no runtime resource
    // bundle or network lookup. Cargo tracks these include_str! inputs.
    let icons = BTreeMap::from([
        (
            "sell",
            include_str!(
                "../../../vendor/@http/https__raw.githubusercontent.com/marella/material-design-icons/refs/heads/main/svg/filled/sell.svg"
            ),
        ),
        (
            "data_object",
            include_str!(
                "../../../vendor/@http/https__raw.githubusercontent.com/marella/material-design-icons/refs/heads/main/svg/filled/data_object.svg"
            ),
        ),
        (
            "lock_open",
            include_str!(
                "../../../vendor/@http/https__raw.githubusercontent.com/marella/material-design-icons/refs/heads/main/svg/filled/lock_open.svg"
            ),
        ),
        (
            "password",
            include_str!(
                "../../../vendor/@http/https__raw.githubusercontent.com/marella/material-design-icons/refs/heads/main/svg/filled/password.svg"
            ),
        ),
        (
            "github",
            include_str!(
                "../../../vendor/@http/https__cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/github/github-original.svg"
            ),
        ),
        (
            "gitlab",
            include_str!(
                "../../../vendor/@http/https__cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/gitlab/gitlab-original.svg"
            ),
        ),
        (
            "bitbucket",
            include_str!(
                "../../../vendor/@http/https__cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/bitbucket/bitbucket-original.svg"
            ),
        ),
        (
            "git",
            include_str!(
                "../../../vendor/@http/https__cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/git/git-original.svg"
            ),
        ),
        (
            "cloud_upload",
            include_str!(
                "../../../vendor/@http/https__raw.githubusercontent.com/marella/material-design-icons/refs/heads/main/svg/filled/cloud_upload.svg"
            ),
        ),
        (
            "cloud_download",
            include_str!(
                "../../../vendor/@http/https__raw.githubusercontent.com/marella/material-design-icons/refs/heads/main/svg/filled/cloud_download.svg"
            ),
        ),
        (
            "commit",
            include_str!(
                "../../../vendor/@http/https__raw.githubusercontent.com/marella/material-design-icons/refs/heads/main/svg/filled/commit.svg"
            ),
        ),
        (
            "key",
            include_str!(
                "../../../vendor/@http/https__raw.githubusercontent.com/marella/material-design-icons/refs/heads/main/svg/filled/key.svg"
            ),
        ),
    ]);
    let json = serde_json::to_string_pretty(
        &serde_json::json!({"labels": labels, "fixtures": fixtures, "icons": icons}),
    )
    .unwrap();
    format!(
        "// Generated by seccy_ui from Fluent. Do not edit.\nlet sharedCopyJSON = #\"\"\"\n{json}\n\"\"\"#\n"
    )
}
