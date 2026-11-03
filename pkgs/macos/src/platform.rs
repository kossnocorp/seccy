use anyhow::{Context, Result, anyhow, bail, ensure};
use seccy_core::{Caller, Identity, KeyStore, Mode};
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

fn label(name: &str, mode: Mode) -> String {
    format!("seccy.v1.{}.{name}", mode.as_str())
}

fn lookup(name: &str, mode: Mode) -> Result<Option<SecKey>> {
    let result = ItemSearchOptions::new()
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
            Mode::Touchid => Mode::Notify,
            Mode::Notify => Mode::Touchid,
        };
        ensure!(
            lookup(name, other)?.is_none(),
            "key {name} already exists with another mode; use a new name to rotate it"
        );
        if let Some(key) = lookup(name, mode)? {
            return Ok((identity(&key, name, mode)?, false));
        }
        let mut flags = kSecAccessControlPrivateKeyUsage;
        if mode == Mode::Touchid {
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

    fn sign(&self, expected: &Identity, message: &[u8], caller: &Caller) -> Result<Vec<u8>> {
        // Fetch a fresh reference for each operation; never cache an authenticated LAContext.
        let key = lookup(&expected.name, expected.mode)?.context("key no longer exists")?;
        ensure!(
            identity(&key, &expected.name, expected.mode)?.blob == expected.blob,
            "key changed; restart agent"
        );
        let signature = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|e| anyhow!("Secure Enclave signing failed: {e}"))?;
        if expected.mode == Mode::Notify {
            notify(&format!(
                "{} used by {} (PID {})",
                expected.name, caller.executable, caller.pid
            ))?;
        }
        Ok(signature)
    }
}

fn notify(message: &str) -> Result<()> {
    // Pass untrusted text as argv, never interpolate it into AppleScript source.
    let output = Command::new("/usr/bin/osascript")
        .args(["-e", "on run argv\ndisplay notification (item 1 of argv) with title \"seccy: key used\"\nend run", "--", message])
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
    let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    ensure!(n > 0, "cannot resolve socket peer executable");
    let end = path.iter().position(|b| *b == 0).unwrap_or(path.len());
    Ok(Caller {
        pid,
        executable: String::from_utf8_lossy(&path[..end]).into_owned(),
    })
}
