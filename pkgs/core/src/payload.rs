//! Interpretation of client-supplied signing bytes, not proof of destination.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    Unknown,
    SshAuthentication {
        username: String,
        service: String,
        method: String,
        algorithm: String,
        session_id_base64: String,
        host: Option<HostKey>,
    },
    SshSignature {
        namespace: String,
        hash_algorithm: String,
        digest_base64: String,
    },
}

#[derive(Debug, Serialize)]
pub struct HostKey {
    pub algorithm: String,
    pub fingerprint: String,
    #[serde(skip)]
    blob: Vec<u8>,
    pub known_hosts: Vec<KnownHost>,
    pub lookup_notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct KnownHost {
    pub file: PathBuf,
    pub line: usize,
    /// None for hashed host fields, whose names cannot be recovered.
    pub names: Option<String>,
    pub hashed: bool,
    pub revoked: bool,
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if len > self.0.len() {
            return None;
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Some(head)
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        self.take(len)
    }
    fn text(&mut self) -> Option<String> {
        let bytes = self.string()?;
        if bytes.is_empty() || bytes.len() > 1024 {
            return None;
        }
        Some(std::str::from_utf8(bytes).ok()?.to_owned())
    }
}

impl Payload {
    pub fn decode(bytes: &[u8], signing_key: &[u8]) -> Self {
        Self::parse(bytes, signing_key).unwrap_or(Self::Unknown)
    }

    fn parse(bytes: &[u8], signing_key: &[u8]) -> Option<Self> {
        if bytes.len() > crate::agent::MAX_FRAME {
            return None;
        }
        let mut reader = Reader(bytes);
        if bytes.starts_with(b"SSHSIG") {
            reader.take(6)?;
            let namespace = reader.text()?;
            if !reader.string()?.is_empty() {
                return None;
            }
            let hash_algorithm = reader.text()?;
            let digest = reader.string()?;
            let length = match hash_algorithm.as_str() {
                "sha256" => 32,
                "sha512" => 64,
                _ => return None,
            };
            if digest.len() != length || !reader.0.is_empty() {
                return None;
            }
            return Some(Self::SshSignature {
                namespace,
                hash_algorithm,
                digest_base64: STANDARD.encode(digest),
            });
        }
        let session = reader.string()?;
        if session.is_empty() || session.len() > 128 || reader.take(1)? != [50] {
            return None;
        }
        let username = reader.text()?;
        let service = reader.text()?;
        if service != "ssh-connection" {
            return None;
        }
        let method = reader.text()?;
        if !matches!(
            method.as_str(),
            "publickey" | "publickey-hostbound-v00@openssh.com"
        ) || reader.take(1)? != [1]
        {
            return None;
        }
        let algorithm = reader.text()?;
        if algorithm.as_bytes() != crate::agent::ALGORITHM || reader.string()? != signing_key {
            return None;
        }
        let host = if method == "publickey-hostbound-v00@openssh.com" {
            let blob = reader.string()?;
            let mut key = Reader(blob);
            let algorithm = key.text()?;
            if key.string()?.is_empty() {
                return None;
            }
            Some(HostKey {
                algorithm,
                fingerprint: format!(
                    "SHA256:{}",
                    STANDARD.encode(Sha256::digest(blob)).trim_end_matches('=')
                ),
                blob: blob.to_vec(),
                known_hosts: Vec::new(),
                lookup_notes: Vec::new(),
            })
        } else {
            None
        };
        if !reader.0.is_empty() {
            return None;
        }
        Some(Self::SshAuthentication {
            username,
            service,
            method,
            algorithm,
            session_id_base64: STANDARD.encode(session),
            host,
        })
    }

    pub fn enrich(&mut self, files: &[PathBuf]) {
        let Self::SshAuthentication {
            host: Some(host), ..
        } = self
        else {
            return;
        };
        for path in files {
            host.lookup(path);
        }
    }

    pub fn description(&self) -> String {
        match self {
            Self::Unknown => "Unrecognized signing payload".into(),
            Self::SshSignature {
                namespace,
                hash_algorithm,
                ..
            } => format!(
                "SSH signature; namespace {namespace:?}; content digest {hash_algorithm}\nRepository and document contents are not included"
            ),
            Self::SshAuthentication {
                username,
                method,
                host,
                ..
            } => {
                let mut text = format!("SSH authentication as {username:?}\nMethod: {method}");
                if let Some(host) = host {
                    text.push_str(&format!(
                        "\nServer key: {:?} {}",
                        host.algorithm, host.fingerprint
                    ));
                    for found in &host.known_hosts {
                        let names = found
                            .names
                            .as_ref()
                            .map(|s| format!("{s:?}"))
                            .unwrap_or_else(|| "hashed hostname (not recoverable)".into());
                        text.push_str(&format!(
                            "\nKnown-host key match: {names}{} ({:?}:{})",
                            if found.revoked { " [REVOKED]" } else { "" },
                            found.file,
                            found.line
                        ));
                    }
                    if host.known_hosts.is_empty() {
                        text.push_str("\nNo matching key in searched known_hosts files");
                    }
                    text.push_str("\nHostnames are key associations, not a verified destination");
                    for note in &host.lookup_notes {
                        text.push_str(&format!("\nLookup: {note:?}"));
                    }
                } else {
                    text.push_str("\nNo server host key included; destination unknown");
                }
                text
            }
        }
    }
}

impl HostKey {
    fn lookup(&mut self, path: &Path) {
        const LIMIT: u64 = 4 * 1024 * 1024;
        // Avoid opening directories/devices/FIFOs supplied as lookup paths.
        match std::fs::metadata(path) {
            Ok(metadata) if !metadata.is_file() => {
                self.lookup_notes
                    .push(format!("{} is not a regular file", path.display()));
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                self.lookup_notes
                    .push(format!("{}: {error}", path.display()));
                return;
            }
            _ => (),
        }
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                self.lookup_notes
                    .push(format!("{}: {error}", path.display()));
                return;
            }
        };
        if !file.metadata().map(|m| m.is_file()).unwrap_or(false) {
            self.lookup_notes
                .push(format!("{} is not a regular file", path.display()));
            return;
        }
        let mut bytes = Vec::new();
        if let Err(error) = file.take(LIMIT + 1).read_to_end(&mut bytes) {
            self.lookup_notes
                .push(format!("{}: {error}", path.display()));
            return;
        }
        if bytes.len() > LIMIT as usize {
            self.lookup_notes
                .push(format!("{} exceeds 4 MiB; skipped", path.display()));
            return;
        }
        for (index, line) in String::from_utf8_lossy(&bytes).lines().enumerate() {
            let mut fields = line.split_whitespace();
            let Some(first) = fields.next() else {
                continue;
            };
            if first.starts_with('#') {
                continue;
            }
            let (names, revoked) = match first {
                "@revoked" => (fields.next().unwrap_or(""), true),
                marker if marker.starts_with('@') => continue,
                names => (names, false),
            };
            if fields.next() != Some(self.algorithm.as_str()) {
                continue;
            }
            let Some(encoded) = fields.next() else {
                continue;
            };
            if STANDARD.decode(encoded).ok().as_deref() != Some(self.blob.as_slice()) {
                continue;
            }
            if self.known_hosts.len() >= 64 {
                self.lookup_notes
                    .push("Additional matches omitted (limit 64)".into());
                return;
            }
            let hashed = names.starts_with('|');
            self.known_hosts.push(KnownHost {
                file: path.into(),
                line: index + 1,
                names: if hashed { None } else { Some(names.into()) },
                hashed,
                revoked,
            });
        }
    }
}

pub fn known_hosts_files() -> Vec<PathBuf> {
    if let Some(value) = std::env::var_os("SECCY_KNOWN_HOSTS") {
        return std::env::split_paths(&value)
            .filter(|p| p.is_absolute())
            .take(16)
            .collect();
    }
    let mut files = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        for name in ["known_hosts", "known_hosts2"] {
            files.push(PathBuf::from(&home).join(".ssh").join(name));
        }
    }
    files.extend([
        PathBuf::from("/etc/ssh/ssh_known_hosts"),
        PathBuf::from("/etc/ssh/ssh_known_hosts2"),
    ]);
    files
}
