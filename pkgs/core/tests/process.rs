use seccy_core::process::{interpret, repository_candidate};

#[test]
fn observed_commands_have_the_same_meaning_on_both_platforms() {
    let args = ["ssh", "-vv", "-p2222", "-l", "alice", "example.com"].map(str::to_owned);
    let result = interpret("/usr/bin/ssh", &args, Some("/work")).unwrap();
    assert_eq!(result.destination_argument.as_deref(), Some("example.com"));
    assert_eq!(result.port_argument.as_deref(), Some("2222"));
    assert_eq!(result.username_argument.as_deref(), Some("alice"));
    let args = ["git", "-C", "project", "--git-dir=metadata", "commit"].map(str::to_owned);
    let result = interpret("/usr/bin/git", &args, Some("/work")).unwrap();
    assert_eq!(result.subcommand.as_deref(), Some("commit"));
    assert_eq!(
        result.effective_directory_candidate.as_deref(),
        Some("/work/project")
    );
    assert_eq!(
        repository_candidate(Some(&result), Some("/work")).as_deref(),
        Some("explicit --git-dir: metadata")
    );
    assert!(interpret("/usr/bin/unknown", &args, None).is_none());
}
