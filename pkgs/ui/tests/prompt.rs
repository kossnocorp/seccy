//! Each pair snapshots the actual serialized Swift presentation contract and
//! its plain text rendering (not a second hand-built expectation).
use seccy_ui::{
    Operation,
    prompt::{ProcessRef, Prompt},
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    operation: Operation,
    processes: Vec<ProcessRef>,
    directory: String,
    keys: Vec<String>,
}
fn prompt(json: &str) -> Prompt {
    let f: Fixture = serde_json::from_str(json).unwrap();
    Prompt::new(&f.operation, f.processes, Some(&f.directory), &f.keys)
}

#[test]
fn git_pull_ghostty_herdr() {
    let model = prompt(include_str!("fixtures/git-pull-ghostty-herdr.json"));
    insta::assert_ron_snapshot!(model, @r#"
    Prompt(
      version: 1,
      title: "Sign in with SSH?",
      rows: [
        [
          Node(
            kind: text,
            value: "Let ",
          ),
          Node(
            kind: processes,
            value: [
              ProcessRef(
                pid: 37403,
                label: "ssh",
              ),
              ProcessRef(
                pid: 37402,
                label: "git fetch",
              ),
              ProcessRef(
                pid: 37400,
                label: "git pull",
              ),
              ProcessRef(
                pid: 33339,
                label: "fish",
              ),
              ProcessRef(
                pid: 33332,
                label: "bash",
              ),
              ProcessRef(
                pid: 59514,
                label: "fish",
              ),
              ProcessRef(
                pid: 21013,
                label: "herdr",
              ),
              ProcessRef(
                pid: 21012,
                label: "herdr",
              ),
              ProcessRef(
                pid: 35446,
                label: "fish",
              ),
              ProcessRef(
                pid: 35444,
                label: "login",
              ),
              ProcessRef(
                pid: 35443,
                label: "ghostty",
              ),
              ProcessRef(
                pid: 1,
                label: "launchd",
              ),
            ],
          ),
        ],
        [
          Node(
            kind: text,
            value: "use ",
          ),
          Node(
            kind: keys,
            value: [
              "auth",
            ],
          ),
          Node(
            kind: text,
            value: " to ",
          ),
          Node(
            kind: action,
            value: "sign in as git@github.com",
          ),
          Node(
            kind: text,
            value: "?",
          ),
        ],
        [
          Node(
            kind: directory,
            value: "/Users/example/code/tmp/seccy-test",
          ),
        ],
      ],
    )
    "#);
    insta::assert_snapshot!(model.text_preview(), @"
    Sign in with SSH?
    Let ssh ‹ git fetch ‹ git pull ‹ …
    use auth to sign in as git@github.com?
    /Users/example/code/tmp/seccy-test
    ");
}

#[test]
fn git_pull_vscode() {
    let model = prompt(include_str!("fixtures/git-pull-vscode.json"));
    insta::assert_ron_snapshot!(model, @r#"
    Prompt(
      version: 1,
      title: "Sign in with SSH?",
      rows: [
        [
          Node(
            kind: text,
            value: "Let ",
          ),
          Node(
            kind: processes,
            value: [
              ProcessRef(
                pid: 44405,
                label: "ssh",
              ),
              ProcessRef(
                pid: 44404,
                label: "git fetch",
              ),
              ProcessRef(
                pid: 44402,
                label: "git pull",
              ),
              ProcessRef(
                pid: 41810,
                label: "fish",
              ),
              ProcessRef(
                pid: 41801,
                label: "bash",
              ),
              ProcessRef(
                pid: 40858,
                label: "fish",
              ),
              ProcessRef(
                pid: 37945,
                label: "Code Helper",
              ),
              ProcessRef(
                pid: 36822,
                label: "Code",
              ),
              ProcessRef(
                pid: 1,
                label: "launchd",
              ),
            ],
          ),
        ],
        [
          Node(
            kind: text,
            value: "use ",
          ),
          Node(
            kind: keys,
            value: [
              "auth",
            ],
          ),
          Node(
            kind: text,
            value: " to ",
          ),
          Node(
            kind: action,
            value: "sign in as git@github.com",
          ),
          Node(
            kind: text,
            value: "?",
          ),
        ],
        [
          Node(
            kind: directory,
            value: "/Users/example/code/tmp/seccy-test",
          ),
        ],
      ],
    )
    "#);
    insta::assert_snapshot!(model.text_preview(), @"
    Sign in with SSH?
    Let ssh ‹ git fetch ‹ git pull ‹ …
    use auth to sign in as git@github.com?
    /Users/example/code/tmp/seccy-test
    ");
}

#[test]
fn git_push_ghostty_herdr() {
    let model = prompt(include_str!("fixtures/git-push-ghostty-herdr.json"));
    insta::assert_ron_snapshot!(model, @r#"
    Prompt(
      version: 1,
      title: "Sign in with SSH?",
      rows: [
        [
          Node(
            kind: text,
            value: "Let ",
          ),
          Node(
            kind: processes,
            value: [
              ProcessRef(
                pid: 39196,
                label: "ssh",
              ),
              ProcessRef(
                pid: 39195,
                label: "git push",
              ),
              ProcessRef(
                pid: 33339,
                label: "fish",
              ),
              ProcessRef(
                pid: 33332,
                label: "bash",
              ),
              ProcessRef(
                pid: 59514,
                label: "fish",
              ),
              ProcessRef(
                pid: 21013,
                label: "herdr",
              ),
              ProcessRef(
                pid: 21012,
                label: "herdr",
              ),
              ProcessRef(
                pid: 35446,
                label: "fish",
              ),
              ProcessRef(
                pid: 35444,
                label: "login",
              ),
              ProcessRef(
                pid: 35443,
                label: "ghostty",
              ),
              ProcessRef(
                pid: 1,
                label: "launchd",
              ),
            ],
          ),
        ],
        [
          Node(
            kind: text,
            value: "use ",
          ),
          Node(
            kind: keys,
            value: [
              "auth",
            ],
          ),
          Node(
            kind: text,
            value: " to ",
          ),
          Node(
            kind: action,
            value: "sign in as git@github.com",
          ),
          Node(
            kind: text,
            value: "?",
          ),
        ],
        [
          Node(
            kind: directory,
            value: "/Users/example/code/tmp/seccy-test",
          ),
        ],
      ],
    )
    "#);
    insta::assert_snapshot!(model.text_preview(), @"
    Sign in with SSH?
    Let ssh ‹ git push ‹ fish ‹ …
    use auth to sign in as git@github.com?
    /Users/example/code/tmp/seccy-test
    ");
}

#[test]
fn git_push_vscode() {
    let model = prompt(include_str!("fixtures/git-push-vscode.json"));
    insta::assert_ron_snapshot!(model, @r#"
    Prompt(
      version: 1,
      title: "Sign in with SSH?",
      rows: [
        [
          Node(
            kind: text,
            value: "Let ",
          ),
          Node(
            kind: processes,
            value: [
              ProcessRef(
                pid: 43828,
                label: "ssh",
              ),
              ProcessRef(
                pid: 43827,
                label: "git push",
              ),
              ProcessRef(
                pid: 41810,
                label: "fish",
              ),
              ProcessRef(
                pid: 41801,
                label: "bash",
              ),
              ProcessRef(
                pid: 40858,
                label: "fish",
              ),
              ProcessRef(
                pid: 37945,
                label: "Code Helper",
              ),
              ProcessRef(
                pid: 36822,
                label: "Code",
              ),
              ProcessRef(
                pid: 1,
                label: "launchd",
              ),
            ],
          ),
        ],
        [
          Node(
            kind: text,
            value: "use ",
          ),
          Node(
            kind: keys,
            value: [
              "auth",
            ],
          ),
          Node(
            kind: text,
            value: " to ",
          ),
          Node(
            kind: action,
            value: "sign in as git@github.com",
          ),
          Node(
            kind: text,
            value: "?",
          ),
        ],
        [
          Node(
            kind: directory,
            value: "/Users/example/code/tmp/seccy-test",
          ),
        ],
      ],
    )
    "#);
    insta::assert_snapshot!(model.text_preview(), @"
    Sign in with SSH?
    Let ssh ‹ git push ‹ fish ‹ …
    use auth to sign in as git@github.com?
    /Users/example/code/tmp/seccy-test
    ");
}

#[test]
fn secret_exec_multi() {
    let model = prompt(include_str!("fixtures/secret-exec-multi.json"));
    insta::assert_ron_snapshot!(model, @r#"
    Prompt(
      version: 1,
      title: "Decrypt secrets?",
      rows: [
        [
          Node(
            kind: text,
            value: "Let ",
          ),
          Node(
            kind: processes,
            value: [
              ProcessRef(
                pid: 49561,
                label: "seccy",
              ),
              ProcessRef(
                pid: 33339,
                label: "fish",
              ),
              ProcessRef(
                pid: 33332,
                label: "bash",
              ),
              ProcessRef(
                pid: 59514,
                label: "fish",
              ),
              ProcessRef(
                pid: 21013,
                label: "herdr",
              ),
              ProcessRef(
                pid: 21012,
                label: "herdr",
              ),
              ProcessRef(
                pid: 35446,
                label: "fish",
              ),
              ProcessRef(
                pid: 35444,
                label: "login",
              ),
              ProcessRef(
                pid: 35443,
                label: "ghostty",
              ),
              ProcessRef(
                pid: 1,
                label: "launchd",
              ),
            ],
          ),
        ],
        [
          Node(
            kind: text,
            value: "use ",
          ),
          Node(
            kind: keys,
            value: [
              "auth",
            ],
          ),
          Node(
            kind: text,
            value: " to ",
          ),
          Node(
            kind: action,
            value: "decrypt",
          ),
          Node(
            kind: text,
            value: " ",
          ),
          Node(
            kind: secrets,
            value: [
              "VERY_SECRET",
              "VERY_SECRET2",
              "VERY_SECRET3",
            ],
          ),
          Node(
            kind: text,
            value: "?",
          ),
        ],
        [
          Node(
            kind: directory,
            value: "/Users/example/code/tmp/seccy-test",
          ),
        ],
      ],
    )
    "#);
    insta::assert_snapshot!(model.text_preview(), @"
    Decrypt secrets?
    Let seccy ‹ fish ‹ bash ‹ …
    use auth to decrypt VERY_SECRET, VERY_SECRET2, VERY_SECRET3?
    /Users/example/code/tmp/seccy-test
    ");
}

#[test]
fn secret_exec_single() {
    let model = prompt(include_str!("fixtures/secret-exec-single.json"));
    insta::assert_ron_snapshot!(model, @r#"
    Prompt(
      version: 1,
      title: "Decrypt a secret?",
      rows: [
        [
          Node(
            kind: text,
            value: "Let ",
          ),
          Node(
            kind: processes,
            value: [
              ProcessRef(
                pid: 48358,
                label: "seccy",
              ),
              ProcessRef(
                pid: 33339,
                label: "fish",
              ),
              ProcessRef(
                pid: 33332,
                label: "bash",
              ),
              ProcessRef(
                pid: 59514,
                label: "fish",
              ),
              ProcessRef(
                pid: 21013,
                label: "herdr",
              ),
              ProcessRef(
                pid: 21012,
                label: "herdr",
              ),
              ProcessRef(
                pid: 35446,
                label: "fish",
              ),
              ProcessRef(
                pid: 35444,
                label: "login",
              ),
              ProcessRef(
                pid: 35443,
                label: "ghostty",
              ),
              ProcessRef(
                pid: 1,
                label: "launchd",
              ),
            ],
          ),
        ],
        [
          Node(
            kind: text,
            value: "use ",
          ),
          Node(
            kind: keys,
            value: [
              "auth",
            ],
          ),
          Node(
            kind: text,
            value: " to ",
          ),
          Node(
            kind: action,
            value: "decrypt",
          ),
          Node(
            kind: text,
            value: " ",
          ),
          Node(
            kind: secrets,
            value: [
              "VERY_SECRET",
            ],
          ),
          Node(
            kind: text,
            value: "?",
          ),
        ],
        [
          Node(
            kind: directory,
            value: "/Users/example/code/tmp/seccy-test",
          ),
        ],
      ],
    )
    "#);
    insta::assert_snapshot!(model.text_preview(), @"
    Decrypt a secret?
    Let seccy ‹ fish ‹ bash ‹ …
    use auth to decrypt VERY_SECRET?
    /Users/example/code/tmp/seccy-test
    ");
}

#[test]
fn secret_get_ghostty_herdr() {
    let model = prompt(include_str!("fixtures/secret-get-ghostty-herdr.json"));
    insta::assert_ron_snapshot!(model, @r#"
    Prompt(
      version: 1,
      title: "Decrypt a secret?",
      rows: [
        [
          Node(
            kind: text,
            value: "Let ",
          ),
          Node(
            kind: processes,
            value: [
              ProcessRef(
                pid: 46840,
                label: "seccy",
              ),
              ProcessRef(
                pid: 33339,
                label: "fish",
              ),
              ProcessRef(
                pid: 33332,
                label: "bash",
              ),
              ProcessRef(
                pid: 59514,
                label: "fish",
              ),
              ProcessRef(
                pid: 21013,
                label: "herdr",
              ),
              ProcessRef(
                pid: 21012,
                label: "herdr",
              ),
              ProcessRef(
                pid: 35446,
                label: "fish",
              ),
              ProcessRef(
                pid: 35444,
                label: "login",
              ),
              ProcessRef(
                pid: 35443,
                label: "ghostty",
              ),
              ProcessRef(
                pid: 1,
                label: "launchd",
              ),
            ],
          ),
        ],
        [
          Node(
            kind: text,
            value: "use ",
          ),
          Node(
            kind: keys,
            value: [
              "auth",
            ],
          ),
          Node(
            kind: text,
            value: " to ",
          ),
          Node(
            kind: action,
            value: "decrypt",
          ),
          Node(
            kind: text,
            value: " ",
          ),
          Node(
            kind: secrets,
            value: [
              "VERY_SECRET",
            ],
          ),
          Node(
            kind: text,
            value: "?",
          ),
        ],
        [
          Node(
            kind: directory,
            value: "/Users/example/code/tmp/seccy-test",
          ),
        ],
      ],
    )
    "#);
    insta::assert_snapshot!(model.text_preview(), @"
    Decrypt a secret?
    Let seccy ‹ fish ‹ bash ‹ …
    use auth to decrypt VERY_SECRET?
    /Users/example/code/tmp/seccy-test
    ");
}

#[test]
fn sign_commit_ghostty_herdr() {
    let model = prompt(include_str!("fixtures/sign-commit-ghostty-herdr.json"));
    insta::assert_ron_snapshot!(model, @r#"
    Prompt(
      version: 1,
      title: "Sign Git commit?",
      rows: [
        [
          Node(
            kind: text,
            value: "Let ",
          ),
          Node(
            kind: processes,
            value: [
              ProcessRef(
                pid: 34767,
                label: "ssh-keygen",
              ),
              ProcessRef(
                pid: 34586,
                label: "git commit",
              ),
              ProcessRef(
                pid: 33339,
                label: "fish",
              ),
              ProcessRef(
                pid: 33332,
                label: "bash",
              ),
              ProcessRef(
                pid: 59514,
                label: "fish",
              ),
              ProcessRef(
                pid: 21013,
                label: "herdr",
              ),
              ProcessRef(
                pid: 21012,
                label: "herdr",
              ),
              ProcessRef(
                pid: 35446,
                label: "fish",
              ),
              ProcessRef(
                pid: 35444,
                label: "login",
              ),
              ProcessRef(
                pid: 35443,
                label: "ghostty",
              ),
              ProcessRef(
                pid: 1,
                label: "launchd",
              ),
            ],
          ),
        ],
        [
          Node(
            kind: text,
            value: "use ",
          ),
          Node(
            kind: keys,
            value: [
              "auth",
            ],
          ),
          Node(
            kind: text,
            value: " to ",
          ),
          Node(
            kind: action,
            value: "sign a Git commit",
          ),
          Node(
            kind: text,
            value: "?",
          ),
        ],
        [
          Node(
            kind: directory,
            value: "/Users/example/code/tmp/seccy-test",
          ),
        ],
      ],
    )
    "#);
    insta::assert_snapshot!(model.text_preview(), @"
    Sign Git commit?
    Let ssh-keygen ‹ git commit ‹ fish ‹ …
    use auth to sign a Git commit?
    /Users/example/code/tmp/seccy-test
    ");
}

#[test]
fn sign_commit_vscode() {
    let model = prompt(include_str!("fixtures/sign-commit-vscode.json"));
    insta::assert_ron_snapshot!(model, @r#"
    Prompt(
      version: 1,
      title: "Sign Git commit?",
      rows: [
        [
          Node(
            kind: text,
            value: "Let ",
          ),
          Node(
            kind: processes,
            value: [
              ProcessRef(
                pid: 43061,
                label: "ssh-keygen",
              ),
              ProcessRef(
                pid: 42969,
                label: "git commit",
              ),
              ProcessRef(
                pid: 41810,
                label: "fish",
              ),
              ProcessRef(
                pid: 41801,
                label: "bash",
              ),
              ProcessRef(
                pid: 40858,
                label: "fish",
              ),
              ProcessRef(
                pid: 37945,
                label: "Code Helper",
              ),
              ProcessRef(
                pid: 36822,
                label: "Code",
              ),
              ProcessRef(
                pid: 1,
                label: "launchd",
              ),
            ],
          ),
        ],
        [
          Node(
            kind: text,
            value: "use ",
          ),
          Node(
            kind: keys,
            value: [
              "auth",
            ],
          ),
          Node(
            kind: text,
            value: " to ",
          ),
          Node(
            kind: action,
            value: "sign a Git commit",
          ),
          Node(
            kind: text,
            value: "?",
          ),
        ],
        [
          Node(
            kind: directory,
            value: "/Users/example/code/tmp/seccy-test",
          ),
        ],
      ],
    )
    "#);
    insta::assert_snapshot!(model.text_preview(), @"
    Sign Git commit?
    Let ssh-keygen ‹ git commit ‹ fish ‹ …
    use auth to sign a Git commit?
    /Users/example/code/tmp/seccy-test
    ");
}
