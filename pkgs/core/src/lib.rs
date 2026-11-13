//! Portable configuration, key-store interface, and OpenSSH agent protocol.
pub mod agent;
pub mod envelope;
pub mod payload;
pub mod process;
mod prompt;
pub mod state;
pub mod storage;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Prompt,
    Notify,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::Notify => "notify",
        }
    }
}

pub mod config;
pub use config::{Config, Github, KeyConfig};

#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub uses: Option<config::Many<config::Use>>,
    pub name: String,
    pub mode: Mode,
    pub public_key: String,
    pub fingerprint: String,
    #[serde(skip)]
    pub blob: Vec<u8>,
}

impl Identity {
    fn prompt_name(&self) -> String {
        self.display_name
            .as_ref()
            .map_or_else(|| self.name.clone(), |n| format!("{} ({n})", self.name))
    }

    pub fn permits(&self, usage: config::Use) -> bool {
        self.uses.as_ref().is_none_or(|u| u.0.contains(&usage))
    }

    pub fn managed_secret_description(&self, name: &str, caller: &Caller) -> String {
        let name = prompt::value(name);
        let heading = match self.mode {
            Mode::Prompt => format!("Decrypt secret {name}?"),
            Mode::Notify => format!("Secret {name} decrypted."),
        };
        caller.request(
            &heading,
            &self.prompt_name(),
            &format!("to decrypt secret {name}"),
            self.mode,
        )
    }

    pub fn sign_description(
        &self,
        _bytes: usize,
        caller: &Caller,
        payload: &payload::Payload,
    ) -> String {
        payload.prompt(&self.prompt_name(), caller, self.mode)
    }

    pub fn decrypt_description(&self, _algorithm: &str, caller: &Caller) -> String {
        caller.request(
            match self.mode {
                Mode::Prompt => "Decrypt a secret?",
                Mode::Notify => "Secret decrypted.",
            },
            &self.prompt_name(),
            "to decrypt a secret",
            self.mode,
        )
    }

    pub fn with_email(mut self, email: Option<&str>) -> Self {
        let comment = email.unwrap_or(&self.name);
        self.public_key = format!(
            "ecdsa-sha2-nistp256 {} {comment}",
            STANDARD.encode(&self.blob)
        );
        self
    }

    pub fn new(name: &str, mode: Mode, point: &[u8]) -> Result<Self> {
        p256::PublicKey::from_sec1_bytes(point).context("invalid P-256 public key")?;
        ensure!(
            point.len() == 65 && point[0] == 4,
            "expected uncompressed P-256 point"
        );
        let mut blob = Vec::new();
        agent::string(&mut blob, agent::ALGORITHM);
        agent::string(&mut blob, b"nistp256");
        agent::string(&mut blob, point);
        Ok(Self {
            display_name: None,
            uses: None,
            name: name.into(),
            mode,
            public_key: format!("ecdsa-sha2-nistp256 {} {name}", STANDARD.encode(&blob)),
            fingerprint: format!(
                "SHA256:{}",
                STANDARD.encode(Sha256::digest(&blob)).trim_end_matches('=')
            ),
            blob,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Caller {
    pub pid: i32,
    pub executable: String,
    pub peer_uid: u32,
    pub peer_gid: u32,
    pub process: Option<ProcessInfo>,
    /// Best-effort OS snapshots, nearest parent first; not authenticated origins.
    pub ancestors: Vec<ProcessInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub parent_pid: i32,
    pub executable: Option<String>,
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub real_uid: u32,
    pub real_gid: u32,
    pub process_group: u32,
    pub start_time_unix_seconds: u64,
    pub start_time_microseconds: u64,
    pub details: ProcessDetails,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ProcessDetails {
    pub observed_at_unix_ms: u128,
    pub collection_duration_ms: u128,
    pub source: String,
    pub working_directory: Option<String>,
    pub terminal_device: Option<u32>,
    pub terminal_foreground_group: Option<u32>,
    pub applications: Vec<ApplicationInfo>,
    pub signing: Option<CodeSigningInfo>,
    /// Included only when debug logging is enabled. Never includes environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
    pub command: Option<CommandInfo>,
    pub repository_candidate: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplicationInfo {
    pub source: String,
    pub bundle_path: String,
    pub identifier: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub build: Option<String>,
    pub executable: Option<String>,
    pub icon_file: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CodeSigningInfo {
    pub source: String,
    pub identifier: Option<String>,
    pub team_identifier: Option<String>,
    pub format: Option<String>,
    pub flags: Option<i64>,
    pub ad_hoc: Option<bool>,
    pub hardened_runtime: Option<bool>,
    pub certificate_subjects: Vec<String>,
    pub cdhash_base64: Option<String>,
    /// OSStatus from local dynamic validation; zero is success, not notarization.
    pub validation_status: i32,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CommandInfo {
    pub source: String,
    pub tool: String,
    pub subcommand: Option<String>,
    pub destination_argument: Option<String>,
    pub username_argument: Option<String>,
    pub port_argument: Option<String>,
    pub effective_directory_candidate: Option<String>,
    pub git_directory_argument: Option<String>,
    pub work_tree_argument: Option<String>,
}

impl ProcessDetails {
    fn description(&self) -> String {
        let mut text = String::new();
        if let Some(cwd) = &self.working_directory {
            text.push_str(&format!("\nWorking directory: {cwd:?}"));
        }
        if let Some(device) = self.terminal_device {
            text.push_str(&format!(
                "\nTerminal device: {device}; foreground group: {:?}",
                self.terminal_foreground_group
            ));
        }
        for app in &self.applications {
            text.push_str(&format!(
                "\nContaining app bundle: {:?}; ID {:?}; version {:?}; path {:?}",
                app.name, app.identifier, app.version, app.bundle_path
            ));
        }
        if let Some(signing) = &self.signing {
            text.push_str(&format!(
                "\nCode signing: ID {:?}; team {:?}; certificates {:?}; local validation OSStatus {}",
                signing.identifier, signing.team_identifier, signing.certificate_subjects, signing.validation_status
            ));
        }
        if let Some(command) = &self.command {
            text.push_str(&format!(
                "\nObserved {} arguments: subcommand {:?}; destination {:?}; user {:?}; port {:?}",
                command.tool,
                command.subcommand,
                command.destination_argument,
                command.username_argument,
                command.port_argument
            ));
        }
        if let Some(repo) = &self.repository_candidate {
            text.push_str(&format!(
                "\nRepository candidate (filesystem/arguments): {repo:?}"
            ));
        }
        text
    }
}

impl Caller {
    pub fn description(&self) -> String {
        let mut text = format!(
            "{} (PID {}, peer UID {}, GID {})",
            self.executable, self.pid, self.peer_uid, self.peer_gid
        );
        if let Some(process) = &self.process {
            text.push_str(&format!("\nProcess: {}; effective UID/GID {}/{}; real UID/GID {}/{}; group {}; started {}.{:06}", process.name, process.uid, process.gid, process.real_uid, process.real_gid, process.process_group, process.start_time_unix_seconds, process.start_time_microseconds));
            text.push_str(&process.details.description());
        }
        for parent in &self.ancestors {
            text.push_str(&format!(
                "\nObserved ancestor: {} (PID {}, UID {})",
                parent.executable.as_deref().unwrap_or(&parent.name),
                parent.pid,
                parent.uid
            ));
            text.push_str(&parent.details.description());
        }
        text
    }
}

/// Implementations return ASN.1 DER ECDSA signatures over SHA-256(message).
pub trait KeyStore {
    fn provision(&self, name: &str, mode: Mode) -> Result<(Identity, bool)>;
    fn identity(&self, name: &str, mode: Mode) -> Result<Option<Identity>>;
    fn sign(
        &self,
        identity: &Identity,
        message: &[u8],
        caller: &Caller,
        payload: &payload::Payload,
    ) -> Result<Vec<u8>>;
}
