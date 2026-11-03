//! Portable configuration, key-store interface, and OpenSSH agent protocol.
pub mod agent;
pub mod storage;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Touchid,
    Notify,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Touchid => "touchid",
            Self::Notify => "notify",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub mode: Mode,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    pub email: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub user: UserConfig,
    #[serde(default)]
    pub keys: BTreeMap<String, KeyConfig>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).context("invalid seccy.toml")?;
        if let Some(email) = &config.user.email {
            ensure!(
                !email.is_empty() && !email.chars().any(|c| c.is_whitespace() || c.is_control()),
                "user.email must be nonempty and contain no whitespace or control characters"
            );
        }
        ensure!(config.keys.len() <= 128, "at most 128 keys are supported");
        for name in config.keys.keys() {
            ensure!(
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
                "key name must contain 1–64 ASCII letters, digits, underscores or hyphens: {name}"
            );
        }
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    pub name: String,
    pub mode: Mode,
    pub public_key: String,
    pub fingerprint: String,
    #[serde(skip)]
    pub blob: Vec<u8>,
}

impl Identity {
    pub fn with_user(mut self, user: &UserConfig) -> Self {
        let comment = user.email.as_deref().unwrap_or(&self.name);
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

#[derive(Clone, Debug, Serialize)]
pub struct Caller {
    pub pid: i32,
    pub executable: String,
}

/// Implementations return ASN.1 DER ECDSA signatures over SHA-256(message).
pub trait KeyStore {
    fn provision(&self, name: &str, mode: Mode) -> Result<(Identity, bool)>;
    fn identity(&self, name: &str, mode: Mode) -> Result<Option<Identity>>;
    fn sign(&self, identity: &Identity, message: &[u8], caller: &Caller) -> Result<Vec<u8>>;
}
