//! Semantic inputs for the Fluent presenter. Legacy descriptions remain separate.
use crate::{Caller, payload::Payload};
pub use seccy_copy::{Activity, Operation, Warning};

impl Caller {
    pub fn activity(&self, key: &str, operation: Operation) -> Activity {
        let (chain, directory) = self.presentation_context();
        Activity {
            operation,
            key: key.into(),
            chain,
            directory,
            warnings: vec![],
        }
    }

    pub fn signing_activity(&self, key: &str, payload: &Payload) -> Activity {
        let operation = match payload {
            Payload::Unknown => Operation::Unknown,
            Payload::SshSignature { namespace, .. } if namespace == "git" => {
                match self.git_operation(&["commit", "tag"]).as_deref() {
                    Some("git commit") => Operation::GitCommit,
                    Some("git tag") => Operation::GitTag,
                    _ => Operation::GitData,
                }
            }
            Payload::SshSignature { namespace, .. } => Operation::Signature {
                namespace: namespace.clone(),
            },
            Payload::SshAuthentication { username, .. } => {
                let command = self
                    .process
                    .as_ref()
                    .and_then(|p| p.details.command.as_ref())
                    .filter(|c| c.tool == "ssh");
                let host =
                    command
                        .and_then(|c| c.destination_argument.as_ref())
                        .map(|destination| {
                            destination
                                .rsplit_once('@')
                                .map_or(destination.as_str(), |(_, host)| host)
                                .into()
                        });
                Operation::Ssh {
                    username: username.clone(),
                    host,
                    port: command.and_then(|c| c.port_argument.clone()),
                    git_operation: self.git_operation(&[
                        "push",
                        "pull",
                        "fetch",
                        "clone",
                        "ls-remote",
                    ]),
                }
            }
        };
        let mut activity = self.activity(key, operation);
        if let Payload::SshAuthentication { host, .. } = payload {
            match host {
                Some(host) => {
                    if host.known_hosts.iter().any(|h| h.revoked) {
                        activity.warnings.push(Warning::Revoked);
                    }
                    if host.known_hosts.is_empty() {
                        activity.warnings.push(Warning::UnknownHost);
                    }
                }
                None => activity.warnings.push(Warning::MissingHost),
            }
        }
        activity
    }
}
