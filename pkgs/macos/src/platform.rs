use anyhow::{Context, Result, anyhow, bail, ensure};
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
        let details = format!(
            "Key: {}\nFingerprint: {}\nMode: {}; algorithm: ECDSA P-256/SHA-256; payload: {} bytes\n{}",
            expected.name,
            expected.fingerprint,
            expected.mode.as_str(),
            message.len(),
            caller.description()
        );
        // Fresh context for every signature, attached to the actual key operation.
        // Keychain ACLs still enforce biometryCurrentSet; this only customizes UI.
        let context = if expected.mode == Mode::Touchid {
            // SAFETY: a newly allocated context is confined to this operation.
            let context = unsafe { LAContext::new() };
            unsafe {
                context.setLocalizedReason(&NSString::from_str(&format!(
                    "Authorize key use.\n{details}"
                )));
                context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
                context.setLocalizedFallbackTitle(Some(&NSString::from_str("")));
            }
            Some(context)
        } else {
            None
        };
        let cf_context = context.as_ref().map(|context| {
            // Security.framework accepts LAContext as a CFType value. Retain
            // under the get rule; both wrappers own their respective references.
            unsafe { CFType::wrap_under_get_rule(Retained::as_ptr(context).cast()) }
        });
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
            notify(&details)?;
            tracing::info!(event = "notification_submitted");
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
    Some(ProcessInfo {
        pid,
        parent_pid: info.pbi_ppid as i32,
        executable: executable(pid),
        name: String::from_utf8_lossy(&name).into_owned(),
        uid: info.pbi_uid,
        gid: info.pbi_gid,
        real_uid: info.pbi_ruid,
        real_gid: info.pbi_rgid,
        process_group: info.pbi_pgid,
        start_time_unix_seconds: info.pbi_start_tvsec,
        start_time_microseconds: info.pbi_start_tvusec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
