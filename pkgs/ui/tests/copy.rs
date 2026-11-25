use seccy_ui::{Activity, Operation, Warning};

fn activity(operation: Operation) -> Activity {
    Activity {
        operation,
        key: "work".into(),
        chain: "Terminal → git commit".into(),
        directory: None,
        warnings: vec![],
    }
}

#[test]
fn complete_sentences_preserve_arguments_and_distinguish_request_from_notification() {
    let mut request = activity(Operation::GitCommit);
    assert_eq!(request.content(false).title, "Approve the git commit?");
    assert_eq!(
        request.content(false).body,
        "The process chain Terminal → git commit wants to use the work key to sign a Git commit."
    );
    request.directory = Some("~/code/project".into());
    assert_eq!(
        request.notification().body,
        "Data signed.\n\nThe process chain Terminal → git commit running at ~/code/project used the work key to sign a Git commit."
    );
    assert_eq!(request.notification().title, "seccy: key used");
}

#[test]
fn every_operation_formats_in_both_modes_without_unresolved_variables() {
    for operation in [
        Operation::Unknown,
        Operation::GitCommit,
        Operation::GitTag,
        Operation::GitData,
        Operation::Signature {
            namespace: "file".into(),
        },
        Operation::Ssh {
            username: "git".into(),
            host: None,
            port: None,
            git_operation: None,
        },
        Operation::Ssh {
            username: "git".into(),
            host: Some("example.com".into()),
            port: Some("2222".into()),
            git_operation: Some("git fetch".into()),
        },
        Operation::Secret { name: None },
        Operation::Secret {
            name: Some("TOKEN".into()),
        },
        Operation::Secrets {
            names: vec!["TOKEN".into(), "DATABASE".into()],
        },
    ] {
        let request = activity(operation);
        for notify in [false, true] {
            let content = request.content(notify);
            assert!(!content.title.is_empty());
            assert!(!content.body.contains("{$"), "{content:?}");
            assert!(
                content
                    .body
                    .contains(if notify { " used " } else { " wants to use " }),
                "{content:?}"
            );
            assert!(content.body.contains("work"));
            assert!(!content.warning);
        }
    }
}

#[test]
fn ssh_port_and_security_warnings_are_explicit() {
    let mut request = activity(Operation::Ssh {
        username: "git".into(),
        host: Some("example.com".into()),
        port: Some("2222".into()),
        git_operation: None,
    });
    request.warnings = vec![Warning::Revoked, Warning::UnknownHost, Warning::MissingHost];
    let content = request.content(false);
    assert!(
        content
            .body
            .contains("to access git@example.com (port 2222).")
    );
    assert!(content.body.contains("[REVOKED]"));
    assert!(content.body.contains("No matching key"));
    assert!(content.body.contains("No server host key"));
    assert!(content.warning);
    assert!(request.notification().body.contains("[REVOKED]"));
    // Warning UI must not be inferred from attacker-controlled text.
    request.warnings.clear();
    request.key = "[REVOKED] No matching key".into();
    assert!(!request.content(false).warning);
}

#[test]
fn values_are_literal_and_controls_cannot_spoof_another_line() {
    let request = activity(Operation::Secret {
        name: Some("**TOKEN** {$key}\n\u{202e}other".into()),
    });
    let content = request.content(false);
    assert_eq!(
        content.title,
        "Decrypt secret **TOKEN** {$key}\\n\\u{202e}other?"
    );
    assert!(!content.body.contains('\n'));
    assert!(!content.body.contains('\u{202e}'));
    assert!(content.body.contains("**TOKEN** {$key}"));
    assert_eq!(seccy_ui::display(&"a".repeat(200)).chars().count(), 161);
}

#[test]
fn checked_in_swift_projection_matches_the_catalog() {
    assert_eq!(
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../macos-ui/Sources/Copy.generated.swift"
        ))
        .unwrap(),
        seccy_ui::swift_source(),
        "Regenerate with cargo run -p seccy_ui --example generate-swift"
    );
}

#[test]
fn provider_matching_is_exact_and_actions_remain_semantic() {
    for (host, provider) in [
        ("github.com", "github"),
        ("SSH.GITHUB.COM.", "github"),
        ("gitlab.com", "gitlab"),
        ("altssh.gitlab.com", "gitlab"),
        ("bitbucket.org", "bitbucket"),
        ("altssh.bitbucket.org", "bitbucket"),
        ("github.com.evil.example", "git"),
        ("my-github-alias", "git"),
        ("git.company.example", "git"),
    ] {
        assert_eq!(seccy_ui::hosting_provider(host), provider);
        for (operation, action) in [
            ("push", "cloud_upload"),
            ("pull", "cloud_download"),
            ("fetch", "cloud_download"),
            ("clone", "cloud_download"),
            ("ls-remote", "cloud_download"),
        ] {
            let header = activity(Operation::Ssh {
                username: "git".into(),
                host: Some(host.into()),
                port: None,
                git_operation: Some(format!("git {operation}")),
            })
            .header("Terminal");
            assert_eq!(header.target, provider);
            assert_eq!(header.action, action);
            assert!(header.title.starts_with("Authorize Git "));
        }
    }
    let header = activity(Operation::GitCommit).header("**App**\u{1}\n");
    assert_eq!(header.target, "git");
    assert_eq!(header.action, "commit");
    assert_eq!(
        header
            .permission
            .iter()
            .filter(|part| part.kind == "app")
            .count(),
        1
    );
    assert_eq!(header.permission[1].value, "**App**\\u{1}\\n");
}
