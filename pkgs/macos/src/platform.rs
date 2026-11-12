use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use core_foundation::base::{CFType, TCFType};
use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_local_authentication::LAContext;
use seccy_core::{Caller, Identity, KeyStore, Mode, ProcessInfo};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::{ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};
use std::{
    os::{fd::AsRawFd, unix::net::UnixStream},
    process::Command,
};

pub struct SecureEnclave;

const ENCRYPTION_ALGORITHM: Algorithm = Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM;
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
const ENVELOPE_PREFIX: &str = "seccy:v1:";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    algorithm: String,
    fingerprint: String,
    ciphertext: String,
}

fn decode_envelope(value: &str, expected: &Identity) -> Result<Vec<u8>> {
    ensure!(value.len() <= 128 * 1024, "ciphertext is too large");
    let encoded = value
        .strip_prefix(ENVELOPE_PREFIX)
        .context("unsupported seccy ciphertext format")?;
    let envelope: Envelope = serde_json::from_slice(
        &STANDARD
            .decode(encoded)
            .context("invalid ciphertext encoding")?,
    )
    .map_err(|_| anyhow!("invalid ciphertext envelope"))?;
    ensure!(
        envelope.algorithm == "ECIES-P256-X963-SHA256-AESGCM",
        "unsupported encryption algorithm"
    );
    ensure!(
        envelope.fingerprint == expected.fingerprint,
        "ciphertext recipient does not match selected key"
    );
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext)
        .context("invalid encrypted payload encoding")?;
    ensure!(
        ciphertext.len() >= 81 && ciphertext.len() <= MAX_SECRET_BYTES + 256,
        "invalid encrypted payload size"
    );
    Ok(ciphertext)
}

impl SecureEnclave {
    pub fn remove(&self, name: &str) -> Result<()> {
        for mode in [Mode::Prompt, Mode::Notify] {
            let result = ItemSearchOptions::new()
                .key_class(KeyClass::private())
                .label(&label(name, mode))
                .case_insensitive(Some(false))
                .ignore_legacy_keychains()
                .delete();
            match result {
                Ok(()) => (),
                Err(e) if e.code() == -25300 => (),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    pub fn managed_names(&self) -> Result<Vec<String>> {
        let result = ItemSearchOptions::new()
            .key_class(KeyClass::private())
            .ignore_legacy_keychains()
            .load_attributes(true)
            .limit(security_framework::item::Limit::All)
            .search();
        let items = match result {
            Ok(items) => items,
            Err(e) if e.code() == -25300 => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut names = Vec::new();
        for item in items {
            if let Some(attributes) = item.simplify_dict()
                && let Some(label) = attributes.get("labl")
            {
                for prefix in ["seccy.v1.prompt.", "seccy.v1.notify."] {
                    if let Some(name) = label.strip_prefix(prefix)
                        && !name.is_empty()
                        && name.len() <= 64
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                    {
                        names.push(name.to_owned());
                    }
                }
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }

    pub fn crypto_check(&self, expected: &Identity) -> Result<()> {
        use security_framework_sys::key::{
            SecKeyIsAlgorithmSupported, kSecKeyOperationTypeDecrypt, kSecKeyOperationTypeEncrypt,
        };
        let key = lookup(&expected.name, expected.mode)?.context("key no longer exists")?;
        ensure!(
            identity(&key, &expected.name, expected.mode)?.blob == expected.blob,
            "key changed; restart agent"
        );
        let public = key.public_key().context("read public key")?;
        // SAFETY: live SecKey references; capability queries perform no private operation.
        let supported = unsafe {
            SecKeyIsAlgorithmSupported(
                key.as_concrete_TypeRef(),
                kSecKeyOperationTypeDecrypt,
                ENCRYPTION_ALGORITHM.into(),
            ) != 0
                && SecKeyIsAlgorithmSupported(
                    public.as_concrete_TypeRef(),
                    kSecKeyOperationTypeEncrypt,
                    ENCRYPTION_ALGORITHM.into(),
                ) != 0
        };
        ensure!(
            supported,
            "key does not support ECIES encryption/decryption"
        );
        Ok(())
    }

    /// Public-key encryption requires no biometric authorization.
    pub fn encrypt(&self, expected: &Identity, plaintext: &[u8]) -> Result<String> {
        ensure!(plaintext.len() <= MAX_SECRET_BYTES, "secret exceeds 64 KiB");
        let key = lookup(&expected.name, expected.mode)?.context("key no longer exists")?;
        ensure!(
            identity(&key, &expected.name, expected.mode)?.blob == expected.blob,
            "key changed; restart agent"
        );
        let public = key.public_key().context("read public key")?;
        encrypt_envelope(&public, expected, plaintext)
    }

    pub fn decrypt(&self, expected: &Identity, value: &str, caller: &Caller) -> Result<Vec<u8>> {
        self.decrypt_secret(expected, value, caller, None)
    }

    /// Share authorization only within this explicitly named batch, never across requests.
    pub fn decrypt_secrets(
        &self,
        items: &[(&Identity, &str, &str)],
        caller: &Caller,
    ) -> Result<Vec<zeroize::Zeroizing<Vec<u8>>>> {
        ensure!(!items.is_empty(), "empty secrets batch");
        let mut ciphertexts = Vec::new();
        for (identity, value, name) in items {
            ensure!(identity.mode == Mode::Prompt, "batch requires prompt keys");
            ensure!(
                seccy_core::envelope::valid_name(name),
                "invalid secret name"
            );
            ciphertexts.push(decode_envelope(value, identity)?);
        }
        let details = caller.managed_secrets_description(
            &items.iter().map(|(_, _, name)| *name).collect::<Vec<_>>(),
            &items
                .iter()
                .map(|(key, _, _)| key.name.as_str())
                .collect::<Vec<_>>(),
        );
        let context = authentication_context(Mode::Prompt, &details);
        let result = (|| {
            let mut plaintexts = Vec::new();
            for ((expected, _, _), ciphertext) in items.iter().zip(ciphertexts) {
                let key =
                    lookup_with_context(&expected.name, expected.mode, as_cf_context(&context))?
                        .context("key no longer exists")?;
                ensure!(
                    identity(&key, &expected.name, expected.mode)?.blob == expected.blob,
                    "key changed; restart agent"
                );
                let plaintext = zeroize::Zeroizing::new(key.decrypt_data(ENCRYPTION_ALGORITHM, &ciphertext)
                    .map_err(|_| anyhow!("decryption failed: authorization cancelled or unavailable, invalidated key, or damaged ciphertext"))?);
                ensure!(
                    plaintext.len() <= MAX_SECRET_BYTES,
                    "decrypted secret exceeds 64 KiB"
                );
                plaintexts.push(plaintext);
            }
            Ok(plaintexts)
        })();
        if let Some(context) = context {
            unsafe {
                context.invalidate();
            }
        }
        result
    }

    /// Name is display context only; managed envelopes authenticate it separately.
    pub fn decrypt_secret(
        &self,
        expected: &Identity,
        value: &str,
        caller: &Caller,
        name: Option<&str>,
    ) -> Result<Vec<u8>> {
        let ciphertext = decode_envelope(value, expected)?;
        let details = if let Some(name) = name {
            ensure!(
                seccy_core::envelope::valid_name(name),
                "invalid secret name"
            );
            expected.managed_secret_description(name, caller)
        } else {
            expected.decrypt_description("ECIES P-256/SHA-256/AES-GCM", caller)
        };
        let context = authentication_context(expected.mode, &details);
        let key = lookup_with_context(&expected.name, expected.mode, as_cf_context(&context))?
            .context("key no longer exists")?;
        ensure!(
            identity(&key, &expected.name, expected.mode)?.blob == expected.blob,
            "key changed; restart agent"
        );
        tracing::info!(event = "decrypt_requested", key = %expected.name, fingerprint = %expected.fingerprint,
            caller_json = %serde_json::to_string(caller)?);
        let plaintext = key.decrypt_data(ENCRYPTION_ALGORITHM, &ciphertext)
            .map_err(|_| anyhow!("decryption failed: authorization cancelled or unavailable, invalidated key, or damaged ciphertext"))?;
        ensure!(
            plaintext.len() <= MAX_SECRET_BYTES,
            "decrypted secret exceeds 64 KiB"
        );
        if expected.mode == Mode::Notify {
            notify("seccy: secret decrypted", &details)?;
            tracing::info!(event = "notification_submitted");
        }
        tracing::info!(event = "secret_decrypted", key = %expected.name);
        Ok(plaintext)
    }
}

fn encrypt_envelope(public: &SecKey, expected: &Identity, plaintext: &[u8]) -> Result<String> {
    ensure!(plaintext.len() <= MAX_SECRET_BYTES, "secret exceeds 64 KiB");
    let ciphertext = public
        .encrypt_data(ENCRYPTION_ALGORITHM, plaintext)
        .map_err(|_| anyhow!("ECIES encryption failed; key or algorithm unavailable"))?;
    let envelope = Envelope {
        algorithm: "ECIES-P256-X963-SHA256-AESGCM".into(),
        fingerprint: expected.fingerprint.clone(),
        ciphertext: STANDARD.encode(ciphertext),
    };
    Ok(format!(
        "{ENVELOPE_PREFIX}{}",
        STANDARD.encode(serde_json::to_vec(&envelope)?)
    ))
}

/// Encrypt to a distributed public recipient without querying any local private key.
pub fn wrap_secret_key(recipient: &str, file_key: &[u8]) -> Result<String> {
    use core_foundation::{
        data::CFData, dictionary::CFDictionary, error::CFError, string::CFString,
    };
    use security_framework_sys::{
        item::{
            kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeyType,
            kSecAttrKeyTypeECSECPrimeRandom,
        },
        key::SecKeyCreateWithData,
    };
    let point = seccy_core::envelope::point(recipient)?;
    let expected = Identity::new("recipient", Mode::Prompt, &point)?;
    // SAFETY: constant attribute strings and CF objects remain live across the call;
    // the returned owned reference is wrapped exactly once.
    let public = unsafe {
        let attributes = CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPublic),
            ),
        ]);
        let data = CFData::from_buffer(&point);
        let mut error = std::ptr::null_mut();
        let key = SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
            &mut error,
        );
        if !error.is_null() {
            let _error = CFError::wrap_under_create_rule(error);
            bail!("cannot import public recipient");
        }
        ensure!(!key.is_null(), "cannot import public recipient");
        SecKey::wrap_under_create_rule(key)
    };
    encrypt_envelope(&public, &expected, file_key)
}

fn authentication_context(mode: Mode, details: &str) -> Option<Retained<LAContext>> {
    if mode != Mode::Prompt {
        return None;
    }
    // SAFETY: this context is confined to one request (a single operation or explicit batch).
    let context = unsafe { LAContext::new() };
    unsafe {
        context.setLocalizedReason(&NSString::from_str(details));
        context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
        context.setLocalizedFallbackTitle(Some(&NSString::from_str("")));
    }
    Some(context)
}

fn as_cf_context(context: &Option<Retained<LAContext>>) -> Option<CFType> {
    context.as_ref().map(|context| {
        // SAFETY: Security.framework accepts LAContext, retained under the get rule.
        unsafe { CFType::wrap_under_get_rule(Retained::as_ptr(context).cast()) }
    })
}

fn label(name: &str, mode: Mode) -> String {
    format!("seccy.v1.{}.{name}", mode.as_str())
}

fn lookup(name: &str, mode: Mode) -> Result<Option<SecKey>> {
    lookup_with_context(name, mode, None)
}

fn lookup_with_context(name: &str, mode: Mode, context: Option<CFType>) -> Result<Option<SecKey>> {
    let result = ItemSearchOptions::new()
        .local_authentication_context(context)
        .key_class(KeyClass::private())
        .label(&label(name, mode))
        .case_insensitive(Some(false))
        .ignore_legacy_keychains()
        .load_refs(true)
        .search();
    match result {
        Ok(items) => match items.into_iter().next() {
            Some(SearchResult::Ref(Reference::Key(key))) => Ok(Some(key)),
            _ => bail!("keychain returned an unexpected item"),
        },
        Err(error) if error.code() == -25300 => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn identity(key: &SecKey, name: &str, mode: Mode) -> Result<Identity> {
    let public = key.public_key().context("read Secure Enclave public key")?;
    let point = public
        .external_representation()
        .context("export public key")?;
    Identity::new(name, mode, point.bytes())
}

impl KeyStore for SecureEnclave {
    fn provision(&self, name: &str, mode: Mode) -> Result<(Identity, bool)> {
        let other = match mode {
            Mode::Prompt => Mode::Notify,
            Mode::Notify => Mode::Prompt,
        };
        ensure!(
            lookup(name, other)?.is_none(),
            "key {name} already exists with another mode; use a new name to rotate it"
        );
        if let Some(key) = lookup(name, mode)? {
            return Ok((identity(&key, name, mode)?, false));
        }
        let mut flags = kSecAccessControlPrivateKeyUsage;
        if mode == Mode::Prompt {
            flags |= kSecAccessControlBiometryCurrentSet;
        }
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            flags,
        )?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(label(name, mode))
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(access);
        let key = SecKey::new(&options).map_err(|e| anyhow!("create Secure Enclave key: {e}"))?;
        Ok((identity(&key, name, mode)?, true))
    }

    fn identity(&self, name: &str, mode: Mode) -> Result<Option<Identity>> {
        lookup(name, mode)?
            .map(|key| identity(&key, name, mode))
            .transpose()
    }

    fn sign(
        &self,
        expected: &Identity,
        message: &[u8],
        caller: &Caller,
        payload: &seccy_core::payload::Payload,
    ) -> Result<Vec<u8>> {
        let details = expected.sign_description(message.len(), caller, payload);
        // Fresh context for every signature, attached to the actual key operation.
        // Keychain ACLs still enforce biometryCurrentSet; this only customizes UI.
        let context = authentication_context(expected.mode, &details);
        let cf_context = as_cf_context(&context);
        let key = lookup_with_context(&expected.name, expected.mode, cf_context)?
            .context("key no longer exists")?;
        ensure!(
            identity(&key, &expected.name, expected.mode)?.blob == expected.blob,
            "key changed; restart agent"
        );
        let signature = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|e| anyhow!("Secure Enclave signing failed: {e}"))?;
        if expected.mode == Mode::Notify {
            notify("seccy: key used", &details)?;
            tracing::info!(event = "notification_submitted");
        }
        Ok(signature)
    }
}

fn notify(title: &str, message: &str) -> Result<()> {
    // Pass untrusted text as argv, never interpolate it into AppleScript source.
    let output = Command::new("/usr/bin/osascript")
        .args(["-e", "on run argv\ndisplay notification (item 1 of argv) with title (item 2 of argv)\nend run", "--", message, title])
        .output().context("send key-use notification")?;
    ensure!(
        output.status.success(),
        "notification failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

pub fn caller(stream: &UnixStream) -> Result<Caller> {
    let fd = stream.as_raw_fd();
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: valid socket and writable uid/gid pointers.
    ensure!(
        unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } == 0,
        "cannot identify socket peer"
    );
    ensure!(
        uid == unsafe { libc::geteuid() },
        "socket peer belongs to another user"
    );
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
    // LOCAL_PEERPID is a kernel-attested PID, not a client-provided agent field.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    ensure!(result == 0 && pid > 0, "cannot identify socket peer PID");
    let executable = executable(pid).context("cannot resolve socket peer executable")?;
    let process = process_info(pid);
    let mut ancestors = Vec::new();
    let mut parent_pid = process.as_ref().map(|p| p.parent_pid).unwrap_or(0);
    while parent_pid > 0 && parent_pid != pid && ancestors.len() < 16 {
        if ancestors.iter().any(|p: &ProcessInfo| p.pid == parent_pid) {
            break;
        }
        let Some(parent) = process_info(parent_pid) else {
            break;
        };
        parent_pid = parent.parent_pid;
        ancestors.push(parent);
    }
    Ok(Caller {
        pid,
        executable,
        peer_uid: uid,
        peer_gid: gid,
        process,
        ancestors,
    })
}

fn executable(pid: i32) -> Option<String> {
    let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: path is a writable buffer of the supplied size.
    let n = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    if n <= 0 {
        return None;
    }
    let end = path.iter().position(|b| *b == 0).unwrap_or(path.len());
    Some(String::from_utf8_lossy(&path[..end]).into_owned())
}

fn process_info(pid: i32) -> Option<ProcessInfo> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: proc_pidinfo writes at most `size` bytes to the allocated struct.
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if read != size {
        return None;
    }
    let info = unsafe { info.assume_init() };
    let name: Vec<u8> = info
        .pbi_name
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as u8)
        .collect();
    let path = executable(pid);
    let details = crate::process::collect(pid, path.as_deref(), info.e_tdev, info.e_tpgid);
    // Discard enrichment if the PID was recycled while inspecting it.
    let mut after = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let reread = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            after.as_mut_ptr().cast(),
            size,
        )
    };
    if reread != size {
        return None;
    }
    let after = unsafe { after.assume_init() };
    if (info.pbi_start_tvsec, info.pbi_start_tvusec)
        != (after.pbi_start_tvsec, after.pbi_start_tvusec)
        || path != executable(pid)
    {
        return None;
    }
    Some(ProcessInfo {
        pid,
        parent_pid: info.pbi_ppid as i32,
        executable: path,
        name: String::from_utf8_lossy(&name).into_owned(),
        uid: info.pbi_uid,
        gid: info.pbi_gid,
        real_uid: info.pbi_ruid,
        real_gid: info.pbi_rgid,
        process_group: info.pbi_pgid,
        start_time_unix_seconds: info.pbi_start_tvsec,
        start_time_microseconds: info.pbi_start_tvusec,
        details,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ephemeral software keys exercise Apple's actual ECIES implementation without
    // creating keychain items or claiming to verify Secure Enclave/Touch ID ACLs.
    fn test_key() -> (SecKey, Identity) {
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256);
        let key = SecKey::new(&options).unwrap();
        let identity = identity(&key, "test", Mode::Prompt).unwrap();
        (key, identity)
    }

    #[test]
    fn ecies_round_trip_preserves_bytes_and_randomizes_ciphertext() {
        let (private, identity) = test_key();
        let public = private.public_key().unwrap();
        for plaintext in [
            vec![],
            b"secret\n\n".to_vec(),
            vec![0, 255, 128],
            vec![42; MAX_SECRET_BYTES],
        ] {
            let a = encrypt_envelope(&public, &identity, &plaintext).unwrap();
            let b = encrypt_envelope(&public, &identity, &plaintext).unwrap();
            assert_ne!(a, b);
            let encrypted = decode_envelope(&a, &identity).unwrap();
            assert_eq!(
                private
                    .decrypt_data(ENCRYPTION_ALGORITHM, &encrypted)
                    .unwrap(),
                plaintext
            );
            let mut tampered = encrypted.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(
                private
                    .decrypt_data(ENCRYPTION_ALGORITHM, &tampered)
                    .is_err()
            );
        }
        assert!(encrypt_envelope(&public, &identity, &vec![0; MAX_SECRET_BYTES + 1]).is_err());
    }

    #[test]
    fn envelopes_reject_wrong_key_versions_algorithms_and_malformed_input() {
        let (private, identity) = test_key();
        let (other, other_identity) = test_key();
        let value = encrypt_envelope(&private.public_key().unwrap(), &identity, b"secret").unwrap();
        assert!(decode_envelope(&value, &other_identity).is_err());
        assert!(
            other
                .decrypt_data(
                    ENCRYPTION_ALGORITHM,
                    &decode_envelope(&value, &identity).unwrap()
                )
                .is_err()
        );
        assert!(decode_envelope(&value.replacen("v1", "v2", 1), &identity).is_err());
        for invalid in ["", "seccy:v1:!", "seccy:v1:e30="] {
            assert!(decode_envelope(invalid, &identity).is_err());
        }
        let mut envelope: serde_json::Value = serde_json::from_slice(
            &STANDARD
                .decode(value.strip_prefix(ENVELOPE_PREFIX).unwrap())
                .unwrap(),
        )
        .unwrap();
        envelope["algorithm"] = serde_json::json!("other");
        let invalid = format!(
            "{ENVELOPE_PREFIX}{}",
            STANDARD.encode(serde_json::to_vec(&envelope).unwrap())
        );
        assert!(decode_envelope(&invalid, &identity).is_err());
        envelope["sensitive-untrusted-field"] = serde_json::json!("do-not-log");
        let invalid = format!(
            "{ENVELOPE_PREFIX}{}",
            STANDARD.encode(serde_json::to_vec(&envelope).unwrap())
        );
        let error = decode_envelope(&invalid, &identity).unwrap_err();
        assert!(!format!("{error:#}").contains("sensitive-untrusted-field"));
    }

    #[test]
    fn public_only_multi_recipient_secrets_use_real_apple_ecies() {
        use seccy_core::envelope;
        let (a, ia) = test_key();
        let (b, ib) = test_key();
        let (_, outsider) = test_key();
        let recipients = vec![
            envelope::from_identity(&ia).unwrap(),
            envelope::from_identity(&ib).unwrap(),
        ];
        for bytes in [
            vec![],
            vec![0, 255, 128, 10],
            vec![42; envelope::MAX_SECRET],
        ] {
            let value = envelope::encrypt("TEST", &bytes, &recipients, wrap_secret_key).unwrap();
            let e = envelope::Envelope::parse(&value, "TEST").unwrap();
            e.matches(&recipients).unwrap();
            for (private, identity) in [(&a, &ia), (&b, &ib)] {
                let encrypted =
                    decode_envelope(&e.wrapped[&identity.fingerprint], identity).unwrap();
                let file_key = private
                    .decrypt_data(ENCRYPTION_ALGORITHM, &encrypted)
                    .unwrap();
                assert_eq!(*e.decrypt(&file_key).unwrap(), bytes);
            }
            assert!(!e.wrapped.contains_key(&outsider.fingerprint));
            assert!(e.matches(&recipients[..1]).is_err());
        }
    }

    #[test]
    fn process_snapshot_matches_current_process() {
        let process = process_info(std::process::id() as i32).unwrap();
        assert_eq!(process.pid, std::process::id() as i32);
        assert_eq!(process.parent_pid, unsafe { libc::getppid() });
        assert_eq!(process.uid, unsafe { libc::geteuid() });
        assert_eq!(process.gid, unsafe { libc::getegid() });
        assert!(process.start_time_unix_seconds > 0);
        assert_eq!(
            process.executable.unwrap(),
            std::env::current_exe().unwrap().to_string_lossy()
        );
    }
}
