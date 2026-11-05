use crate::native;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload as AeadPayload},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use fs2::FileExt;
use p256::{PublicKey, ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint};
use rand_core::{OsRng, RngCore};
use seccy_core::{Caller, Identity, KeyStore, Mode, payload::Payload, storage::Paths};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::Mutex,
};
use zeroize::Zeroizing;

pub const MAX_SECRET_BYTES: usize = 64 * 1024;
static NATIVE: Mutex<()> = Mutex::new(());
pub struct Vault;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u32,
    vault: String,
    user: [u8; 32],
    salt: [u8; 32],
    credential: Vec<u8>,
    credential_public: Vec<u8>,
    parent: Vec<u8>,
    keys: BTreeMap<String, Record>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    #[serde(default)]
    deleting: bool,
    point: Vec<u8>,
    /// Journal a completed key creation until Secret Service and the catalog agree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<String>,
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn directory() -> Result<PathBuf> {
    let path = Paths::from_env()?.state;
    match fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&path)
    {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "vault directory must be owned, private, and not a symlink"
    );
    Ok(path)
}

fn lock() -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory()?.join("linux-vault.lock"))?;
    ensure!(
        file.metadata()?.uid() == unsafe { libc::geteuid() },
        "vault lock belongs to another user"
    );
    file.try_lock_exclusive()
        .context("another vault operation is in progress")?;
    Ok(file)
}

impl Enrollment {
    fn load() -> Result<Self> {
        let path = directory()?.join("linux-vault.json");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .context("Linux vault is not initialized; run seccy init")?;
        ensure!(
            file.metadata()?.len() <= 1024 * 1024,
            "vault metadata is too large"
        );
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1024 * 1024, "vault metadata is too large");
        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid Linux vault metadata"))?;
        ensure!(
            state.version == 1
                && state.parent.len() == 34
                && state.credential_public.len() == 64
                && !state.credential.is_empty()
                && state.credential.len() <= 4096
                && state.keys.len() <= 128,
            "unsupported or invalid vault enrollment"
        );
        Ok(state)
    }
    fn save(&self) -> Result<()> {
        let directory = directory()?;
        let mut file = tempfile::NamedTempFile::new_in(&directory)?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.as_file().sync_all()?;
        file.persist(directory.join("linux-vault.json"))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }
    fn check_tpm(&self) -> Result<()> {
        let (_, parent) = native::tpm(0, &[0; 32], &mut Vec::new(), &[])?;
        ensure!(
            parent == self.parent,
            "TPM identity changed; vault cannot be unlocked"
        );
        Ok(())
    }
    fn unlock(&self, details: &str) -> Result<Zeroizing<[u8; 32]>> {
        self.check_tpm()?;
        let devices = native::devices()?;
        ensure!(
            !devices.is_empty(),
            "enrolled FIDO authenticator is not connected"
        );
        // Require explicit selection if several devices are present: probing UV-protected
        // credentials is not reliably silent and must not produce a series of prompts.
        ensure!(
            devices.len() == 1,
            "connect only the enrolled FIDO authenticator for this operation"
        );
        let mut hash = Sha256::new();
        hash.update(random::<32>());
        hash.update(details.as_bytes());
        let challenge: [u8; 32] = hash.finalize().into();
        let result = native::fido(
            &devices[0],
            &self.user,
            &challenge,
            &self.salt,
            Some((&self.credential, &self.credential_public)),
            details,
        )?;
        let marker = native::secret(&self.vault, "enrollment", None, false)?
            .context("vault enrollment record is missing")?;
        let key = derive(&result.secret[..], &self.vault, "enrollment")?;
        ensure!(
            open(&key, &marker, self.vault.as_bytes())?.as_slice() == b"seccy-vault-v1",
            "vault verification failed"
        );
        Ok(result.secret)
    }
    fn identity(&self, name: &str, mode: Mode) -> Result<Option<Identity>> {
        if let Some(record) = self.keys.get(name) {
            ensure!(
                mode == Mode::Prompt,
                "Linux TPM/FIDO keys require mode=prompt"
            );
            return Ok(Some(Identity::new(name, mode, &record.point)?));
        }
        Ok(None)
    }
}

fn derive(secret: &[u8], vault: &str, purpose: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(vault.as_bytes()), secret)
        .expand(purpose.as_bytes(), &mut *key)
        .map_err(|_| anyhow::anyhow!("key derivation failed"))?;
    Ok(key)
}

fn seal(key: &[u8; 32], bytes: &[u8], aad: &[u8]) -> Result<String> {
    let nonce = random::<12>();
    let encrypted = Aes256Gcm::new_from_slice(key)?
        .encrypt(&Nonce::from(nonce), AeadPayload { msg: bytes, aad })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok(B64.encode([nonce.as_slice(), &encrypted].concat()))
}

fn open(key: &[u8; 32], encoded: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(encoded.len() <= 128 * 1024, "encrypted record is too large");
    let bytes = B64.decode(encoded).context("invalid encrypted record")?;
    ensure!(bytes.len() >= 28, "truncated encrypted record");
    let nonce: [u8; 12] = bytes[..12].try_into()?;
    let plaintext = Aes256Gcm::new_from_slice(key)?
        .decrypt(
            &Nonce::from(nonce),
            AeadPayload {
                msg: &bytes[12..],
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypted record authentication failed"))?;
    Ok(Zeroizing::new(plaintext))
}

pub fn initialize(device: Option<&str>, list: bool) -> Result<serde_json::Value> {
    let _native = NATIVE
        .lock()
        .map_err(|_| anyhow::anyhow!("native lock poisoned"))?;
    let _lock = lock()?;
    if list {
        return Ok(serde_json::json!({"ok": true, "devices": native::devices()?}));
    }
    if directory()?.join("linux-vault.json").try_exists()? {
        let state = Enrollment::load()?;
        return Ok(
            serde_json::json!({"ok": true, "initialized": true, "created": false, "vault": state.vault}),
        );
    }
    let devices = native::devices()?;
    let device = match device {
        Some(device) => {
            ensure!(
                devices.iter().any(|d| d == device),
                "selected FIDO device is not connected"
            );
            device.to_owned()
        }
        None => {
            ensure!(
                devices.len() == 1,
                "connect one FIDO key or choose with seccy init --list and --device"
            );
            devices[0].clone()
        }
    };
    let (_, parent) = native::tpm(0, &[0; 32], &mut Vec::new(), &[])?;
    let user = random::<32>();
    let salt = random::<32>();
    let credential = native::fido(
        &device,
        &user,
        &random::<32>(),
        &salt,
        None,
        "Initialize Seccy on this computer. Enroll a dedicated credential; verify on your security key or enter its PIN and touch it.",
    )?;
    let vault = B64.encode(random::<32>());
    let key = derive(&credential.secret[..], &vault, "enrollment")?;
    let marker = seal(&key, b"seccy-vault-v1", vault.as_bytes())?;
    native::secret(&vault, "enrollment", Some(&marker), false)?;
    let state = Enrollment {
        version: 1,
        vault,
        user,
        salt,
        credential: credential.id,
        credential_public: credential.public,
        parent,
        keys: BTreeMap::new(),
    };
    state.save()?;
    Ok(serde_json::json!({"ok": true, "initialized": true, "created": true, "vault": state.vault}))
}

impl KeyStore for Vault {
    fn identity(&self, name: &str, mode: Mode) -> Result<Option<Identity>> {
        if !directory()?.join("linux-vault.json").try_exists()? {
            return Ok(None);
        }
        Enrollment::load()?.identity(name, mode)
    }
    fn provision(&self, name: &str, mode: Mode) -> Result<(Identity, bool)> {
        ensure!(
            mode == Mode::Prompt,
            "Linux TPM/FIDO keys require mode=prompt; unattended notify mode is not supported"
        );
        let _native = NATIVE
            .lock()
            .map_err(|_| anyhow::anyhow!("native lock poisoned"))?;
        let _lock = lock()?;
        let mut state = Enrollment::load()?;
        if let Some(identity) = state.identity(name, mode)? {
            ensure!(
                !state.keys[name].deleting,
                "key deletion is pending; repeat remove before provisioning"
            );
            if let Some(encrypted) = state.keys.get(name).and_then(|r| r.pending.as_deref()) {
                let _authorization =
                    state.unlock(&format!("Finish provisioning Seccy key {name:?}"))?;
                native::secret(&state.vault, &format!("key/{name}"), Some(encrypted), false)?;
                state.keys.get_mut(name).context("key disappeared")?.pending = None;
                state.save()?;
            } else {
                ensure!(
                    native::secret(&state.vault, &format!("key/{name}"), None, false)?.is_some(),
                    "encrypted TPM key is missing; restore its keychain record or explicitly remove it before replacing it"
                );
            }
            return Ok((identity, false));
        }
        ensure!(state.keys.len() < 128, "vault key limit reached");
        let secret = state.unlock(&format!("Create Seccy key {name:?} on this TPM"))?;
        let auth = derive(&secret[..], &state.vault, &format!("tpm-auth/{name}"))?;
        let wrapping = derive(&secret[..], &state.vault, &format!("wrap/{name}"))?;
        let mut blob = Zeroizing::new(Vec::new());
        let (point, parent) = native::tpm(1, &auth, &mut blob, &[])?;
        ensure!(parent == state.parent, "TPM identity changed");
        let identity = Identity::new(name, mode, &point)?;
        let encrypted = seal(&wrapping, &blob, identity.fingerprint.as_bytes())?;
        state.keys.insert(
            name.into(),
            Record {
                deleting: false,
                point,
                pending: Some(encrypted.clone()),
            },
        );
        state.save()?;
        native::secret(
            &state.vault,
            &format!("key/{name}"),
            Some(&encrypted),
            false,
        )?;
        state.keys.get_mut(name).context("key disappeared")?.pending = None;
        state.save()?;
        Ok((identity, true))
    }
    fn sign(
        &self,
        identity: &Identity,
        message: &[u8],
        caller: &Caller,
        payload: &Payload,
    ) -> Result<Vec<u8>> {
        let details = identity.sign_description(message.len(), caller, payload);
        let bytes = self.operate(identity, 2, &Sha256::digest(message), &details)?;
        Ok(p256::ecdsa::Signature::from_slice(&bytes)?
            .to_der()
            .as_bytes()
            .to_vec())
    }
}

impl Vault {
    fn operate(
        &self,
        identity: &Identity,
        operation: i32,
        input: &[u8],
        details: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let _native = NATIVE
            .lock()
            .map_err(|_| anyhow::anyhow!("native lock poisoned"))?;
        let _lock = lock()?;
        let state = Enrollment::load()?;
        let actual = state
            .identity(&identity.name, identity.mode)?
            .context("key missing from vault")?;
        ensure!(
            !state.keys[&identity.name].deleting,
            "key deletion is pending"
        );
        ensure!(actual.blob == identity.blob, "key identity changed");
        let encrypted =
            native::secret(&state.vault, &format!("key/{}", identity.name), None, false)?
                .context("encrypted TPM key is missing; restore it rather than reprovisioning")?;
        let secret = state.unlock(details)?;
        let wrapping = derive(
            &secret[..],
            &state.vault,
            &format!("wrap/{}", identity.name),
        )?;
        let auth = derive(
            &secret[..],
            &state.vault,
            &format!("tpm-auth/{}", identity.name),
        )?;
        let mut blob = open(&wrapping, &encrypted, identity.fingerprint.as_bytes())?;
        let (result, parent) = native::tpm(operation, &auth, &mut blob, input)?;
        ensure!(parent == state.parent, "TPM identity changed");
        Ok(Zeroizing::new(result))
    }
    pub fn managed_names(&self) -> Result<Vec<String>> {
        if !directory()?.join("linux-vault.json").try_exists()? {
            return Ok(Vec::new());
        }
        Ok(Enrollment::load()?.keys.into_keys().collect())
    }
    pub fn remove(&self, name: &str) -> Result<()> {
        if !directory()?.join("linux-vault.json").try_exists()? {
            return Ok(());
        }
        let _native = NATIVE
            .lock()
            .map_err(|_| anyhow::anyhow!("native lock poisoned"))?;
        let _lock = lock()?;
        let mut state = Enrollment::load()?;
        if !state.keys.contains_key(name) {
            return Ok(());
        }
        let secret = state.unlock(&format!("Permanently remove Seccy key {name:?}"))?;
        let record = state.keys.get(name).context("key disappeared")?;
        let encrypted = match &record.pending {
            Some(value) => Some(value.clone()),
            None => native::secret(&state.vault, &format!("key/{name}"), None, false)?,
        };
        if let Some(encrypted) = encrypted {
            let identity = Identity::new(name, Mode::Prompt, &record.point)?;
            let wrapping = derive(&secret[..], &state.vault, &format!("wrap/{name}"))?;
            let mut blob = open(&wrapping, &encrypted, identity.fingerprint.as_bytes())?;
            // Keep the encrypted blob available if deletion is interrupted.
            let record = state.keys.get_mut(name).context("key disappeared")?;
            record.pending = Some(encrypted);
            record.deleting = true;
            state.save()?;
            crate::broker::request(4, &[0; 32], &mut blob, &[])?;
        }
        native::secret(&state.vault, &format!("key/{name}"), None, true)?;
        state.keys.remove(name);
        state.save()
    }
    pub fn crypto_check(&self, identity: &Identity) -> Result<()> {
        let _native = NATIVE
            .lock()
            .map_err(|_| anyhow::anyhow!("native lock poisoned"))?;
        let state = Enrollment::load()?;
        let actual = state
            .identity(&identity.name, identity.mode)?
            .context("key missing")?;
        ensure!(actual.blob == identity.blob, "key changed");
        state.check_tpm()?;
        ensure!(
            !native::devices()?.is_empty(),
            "FIDO authenticator is not connected"
        );
        ensure!(
            native::secret(&state.vault, &format!("key/{}", identity.name), None, false)?.is_some(),
            "encrypted TPM key missing"
        );
        Ok(())
    }
    pub fn encrypt(&self, identity: &Identity, plaintext: &[u8]) -> Result<String> {
        ensure!(plaintext.len() <= MAX_SECRET_BYTES, "secret exceeds 64 KiB");
        let state = Enrollment::load()?;
        let record = state.keys.get(&identity.name).context("key missing")?;
        ensure!(
            state
                .identity(&identity.name, identity.mode)?
                .context("key missing")?
                .blob
                == identity.blob,
            "key changed"
        );
        let public = PublicKey::from_sec1_bytes(&record.point)?;
        let ephemeral = EphemeralSecret::random(&mut OsRng);
        let point = PublicKey::from(&ephemeral).to_encoded_point(false);
        let shared = ephemeral.diffie_hellman(&public);
        let key = derive(
            shared.raw_secret_bytes(),
            &identity.fingerprint,
            "seccy-linux-ecdh-v1",
        )?;
        let envelope = Ciphertext {
            fingerprint: identity.fingerprint.clone(),
            ephemeral: B64.encode(point.as_bytes()),
            ciphertext: seal(&key, plaintext, identity.fingerprint.as_bytes())?,
        };
        Ok(format!(
            "seccy:linux:v1:{}",
            B64.encode(serde_json::to_vec(&envelope)?)
        ))
    }
    pub fn decrypt(&self, identity: &Identity, value: &str, caller: &Caller) -> Result<Vec<u8>> {
        ensure!(value.len() <= 128 * 1024, "ciphertext too large");
        let Some(encoded) = value.strip_prefix("seccy:linux:v1:") else {
            bail!(
                "unsupported ciphertext format; macOS Secure Enclave ciphertext cannot be decrypted by Linux keys"
            );
        };
        let envelope: Ciphertext = serde_json::from_slice(
            &B64.decode(encoded)
                .map_err(|_| anyhow::anyhow!("invalid ciphertext"))?,
        )
        .map_err(|_| anyhow::anyhow!("invalid ciphertext envelope"))?;
        ensure!(
            envelope.fingerprint == identity.fingerprint,
            "ciphertext recipient does not match key"
        );
        let point = B64
            .decode(envelope.ephemeral)
            .map_err(|_| anyhow::anyhow!("invalid ephemeral key"))?;
        PublicKey::from_sec1_bytes(&point).context("invalid ephemeral key")?;
        ensure!(
            point.len() == 65 && point[0] == 4,
            "expected uncompressed ephemeral key"
        );
        let details = identity.decrypt_description("ECDH P-256/HKDF-SHA256/AES-256-GCM", caller);
        tracing::info!(event = "decrypt_requested", key = %identity.name, caller_json = %serde_json::to_string(caller)?);
        let shared = self.operate(identity, 3, &point, &details)?;
        let key = derive(&shared, &identity.fingerprint, "seccy-linux-ecdh-v1")?;
        let plaintext = open(&key, &envelope.ciphertext, identity.fingerprint.as_bytes())?;
        ensure!(plaintext.len() <= MAX_SECRET_BYTES, "secret exceeds 64 KiB");
        tracing::info!(event = "secret_decrypted", key = %identity.name);
        Ok(plaintext.to_vec())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ciphertext {
    fingerprint: String,
    ephemeral: String,
    ciphertext: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_rejects_wrong_token_vault_key_identity_and_modified_bytes() {
        let fido = random::<32>();
        let key = derive(&fido, "vault-a", "wrap/personal").unwrap();
        let wrapped = seal(&key, b"TPM object bytes", b"public fingerprint").unwrap();
        assert_eq!(
            open(&key, &wrapped, b"public fingerprint")
                .unwrap()
                .as_slice(),
            b"TPM object bytes"
        );
        for wrong in [
            derive(&random::<32>(), "vault-a", "wrap/personal").unwrap(),
            derive(&fido, "vault-b", "wrap/personal").unwrap(),
            derive(&fido, "vault-a", "wrap/other").unwrap(),
            derive(&fido, "vault-a", "tpm-auth/personal").unwrap(),
        ] {
            assert!(open(&wrong, &wrapped, b"public fingerprint").is_err());
        }
        assert!(open(&key, &wrapped, b"different identity").is_err());
        let mut bytes = B64.decode(&wrapped).unwrap();
        bytes[15] ^= 1;
        assert!(open(&key, &B64.encode(bytes), b"public fingerprint").is_err());
    }

    #[test]
    fn ecdh_encryption_preserves_binary_data_and_rejects_wrong_recipient() {
        let recipient = EphemeralSecret::random(&mut OsRng);
        let ephemeral = EphemeralSecret::random(&mut OsRng);
        let encryption = ephemeral.diffie_hellman(&PublicKey::from(&recipient));
        let decryption = recipient.diffie_hellman(&PublicKey::from(&ephemeral));
        let key = derive(
            encryption.raw_secret_bytes(),
            "fingerprint",
            "seccy-linux-ecdh-v1",
        )
        .unwrap();
        let decrypt_key = derive(
            decryption.raw_secret_bytes(),
            "fingerprint",
            "seccy-linux-ecdh-v1",
        )
        .unwrap();
        let bytes = b"\0\xffbinary\n\n";
        let ciphertext = seal(&key, bytes, b"fingerprint").unwrap();
        assert_eq!(
            open(&decrypt_key, &ciphertext, b"fingerprint")
                .unwrap()
                .as_slice(),
            bytes
        );
        assert!(open(&decrypt_key, &ciphertext, b"other fingerprint").is_err());
        assert!(open(&decrypt_key, "", b"fingerprint").is_err());
    }

    #[test]
    #[ignore = "requires accessible physical TPM; creates only transient test objects"]
    fn physical_tpm_signing_and_ecdh() {
        use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
        let _guard = NATIVE.lock().unwrap();
        let auth = random::<32>();
        let mut blob = Vec::new();
        let (point, parent) = native::tpm(1, &auth, &mut blob, &[]).unwrap();
        let digest = Sha256::digest(b"Seccy TPM integration test");
        let (signature, same_parent) = native::tpm(2, &auth, &mut blob, &digest).unwrap();
        assert_eq!(parent, same_parent);
        VerifyingKey::from_sec1_bytes(&point)
            .unwrap()
            .verify_prehash(&digest, &Signature::from_slice(&signature).unwrap())
            .unwrap();
        let ephemeral = EphemeralSecret::random(&mut OsRng);
        let public = PublicKey::from(&ephemeral).to_encoded_point(false);
        let expected = ephemeral.diffie_hellman(&PublicKey::from_sec1_bytes(&point).unwrap());
        let (shared, _) = native::tpm(3, &auth, &mut blob, public.as_bytes()).unwrap();
        assert_eq!(shared.as_slice(), &expected.raw_secret_bytes()[..]);
    }
}
