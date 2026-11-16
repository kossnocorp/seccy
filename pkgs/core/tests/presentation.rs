use seccy_core::{
    Caller, CommandInfo, Identity, Mode, ProcessDetails, ProcessInfo, payload::Payload,
};

fn caller() -> Caller {
    Caller {
        pid: 42,
        executable: "/usr/bin/git".into(),
        peer_uid: 501,
        peer_gid: 20,
        process: Some(ProcessInfo {
            pid: 42,
            parent_pid: 1,
            executable: Some("/usr/bin/git".into()),
            name: "git".into(),
            uid: 501,
            gid: 20,
            real_uid: 501,
            real_gid: 20,
            process_group: 42,
            start_time_unix_seconds: 0,
            start_time_microseconds: 0,
            details: ProcessDetails {
                repository_candidate: Some("/repo".into()),
                command: Some(CommandInfo {
                    tool: "git".into(),
                    subcommand: Some("commit".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        }),
        ancestors: vec![],
    }
}
fn identity() -> Identity {
    Identity {
        name: "work".into(),
        mode: Mode::Prompt,
        public_key: String::new(),
        fingerprint: String::new(),
        blob: vec![],
    }
}
fn signature() -> Payload {
    Payload::SshSignature {
        namespace: "git".into(),
        hash_algorithm: "sha512".into(),
        digest_base64: String::new(),
    }
}

#[test]
fn legacy_prompt_copy_is_byte_for_byte_unchanged() {
    let caller = caller();
    let identity = identity();
    assert_eq!(
        identity.sign_description(0, &caller, &signature()),
        "Approve the git commit?\n\nThe process chain git commit running at /repo wants to use the work key to sign a Git commit."
    );
    assert_eq!(
        identity.decrypt_description("ignored", &caller),
        "Decrypt a secret?\n\nThe process chain git commit running at /repo wants to use the work key to decrypt a secret."
    );
    assert_eq!(
        identity.managed_secret_description("TOKEN", &caller),
        "Decrypt secret TOKEN?\n\nThe process chain git commit running at /repo wants to use the work key to decrypt secret TOKEN."
    );
    assert_eq!(
        caller.managed_secrets_description(&["A", "B"], &["work", "other"]),
        "Decrypt secrets A, B?\n\nThe process chain git commit running at /repo wants to use the work, other key to decrypt secrets A, B."
    );
}

#[test]
fn semantic_presenter_keeps_git_context_and_handles_missing_ssh_host() {
    let caller = caller();
    let identity = identity();
    let activity = caller.signing_activity("work", &signature());
    let content = activity.content(false);
    assert_eq!(
        format!("{}\n\n{}", content.title, content.body),
        identity.sign_description(0, &caller, &signature())
    );
    assert!(activity.notification().body.contains(" used the work key "));
    let ssh = Payload::SshAuthentication {
        username: "git".into(),
        service: "ssh-connection".into(),
        method: "publickey".into(),
        algorithm: String::new(),
        session_id_base64: String::new(),
        host: None,
    };
    let content = caller.signing_activity("work", &ssh).content(false);
    assert!(content.warning);
    assert_eq!(content.title, "Approve this SSH authentication?");
    assert!(content.body.contains("to authenticate over SSH as git."));
    assert!(content.body.contains("No server host key included"));
    assert_eq!(
        identity.sign_description(0, &caller, &ssh),
        "Approve this SSH authentication?\n\nThe process chain git commit running at /repo wants to use the work key to authenticate over SSH as git.\n\nNo server host key included"
    );
}
