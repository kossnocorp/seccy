//! Read-only, best-effort process observations. No subprocesses, UI access, or
//! process environments; interpretations are candidates, not authenticated intent.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType},
    data::CFData,
    dictionary::{CFDictionary, CFDictionaryRef},
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use seccy_core::process::{interpret, repository};
use seccy_core::{ApplicationInfo, CodeSigningInfo, ProcessDetails};
use security_framework::certificate::SecCertificate;
use security_framework::os::macos::code_signing::{Flags, GuestAttributes, SecCode};
use security_framework_sys::code_signing::{SecCodeCheckValidity, SecCodeRef};
use std::{
    fs::File,
    io::Read,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

// These public Security.framework declarations aren't exposed by the Rust sys crate.
unsafe extern "C" {
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoFormat: CFStringRef;
    static kSecCodeInfoFlags: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoCertificates: CFStringRef;
}

pub fn collect(
    pid: i32,
    executable: Option<&str>,
    terminal: u32,
    foreground: u32,
) -> ProcessDetails {
    let started = std::time::Instant::now();
    let mut details = ProcessDetails {
        observed_at_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
        source: "macOS proc_pidinfo, sysctl(KERN_PROCARGS2), Security.framework; bundle/filesystem observations".into(),
        terminal_device: (terminal != u32::MAX).then_some(terminal),
        terminal_foreground_group: (terminal != u32::MAX).then_some(foreground),
        ..Default::default()
    };
    match cwd(pid) {
        Ok(path) => details.working_directory = Some(path),
        Err(error) => details.notes.push(format!("working_directory: {error:#}")),
    }
    if let Some(path) = executable {
        details.applications = applications(Path::new(path), &mut details.notes);
    }
    match signing(pid) {
        Ok(info) => details.signing = Some(info),
        Err(error) => details.notes.push(format!("code_signing: {error:#}")),
    }
    match arguments(pid) {
        Ok(args) => {
            details.command = interpret(
                executable.unwrap_or(""),
                &args,
                details.working_directory.as_deref(),
            );
            if tracing::enabled!(tracing::Level::DEBUG) {
                details.arguments = Some(args);
            }
        }
        Err(error) => details.notes.push(format!("arguments: {error:#}")),
    }
    let candidate = details
        .command
        .as_ref()
        .and_then(|c| c.effective_directory_candidate.as_deref())
        .or(details.working_directory.as_deref());
    if let Some(git_dir) = details
        .command
        .as_ref()
        .and_then(|c| c.git_directory_argument.as_deref())
    {
        details.repository_candidate = Some(format!("explicit --git-dir: {git_dir}"));
    } else if let Some(work_tree) = details
        .command
        .as_ref()
        .and_then(|c| c.work_tree_argument.as_deref())
    {
        details.repository_candidate = Some(format!("explicit --work-tree: {work_tree}"));
    } else if let Some(path) = candidate {
        details.repository_candidate = repository(Path::new(path));
    }
    details.collection_duration_ms = started.elapsed().as_millis();
    details
}

fn cwd(pid: i32) -> Result<String> {
    let mut info = std::mem::MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
    let size = std::mem::size_of_val(&info) as i32;
    // SAFETY: valid writable buffer of exactly the supplied size.
    let count = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    ensure!(
        count == size,
        "proc_pidinfo: {}",
        std::io::Error::last_os_error()
    );
    let info = unsafe { info.assume_init() };
    let path: Vec<_> = info
        .pvi_cdir
        .vip_path
        .iter()
        .flatten()
        .take_while(|b| **b != 0)
        .map(|b| *b as u8)
        .collect();
    ensure!(!path.is_empty(), "path unavailable");
    String::from_utf8(path).context("non-UTF-8 working directory")
}

fn arguments(pid: i32) -> Result<Vec<String>> {
    // A fixed cap bounds memory even if the queried process is hostile.
    let mut data = vec![0u8; 1024 * 1024];
    let mut size = data.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let status = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            data.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    ensure!(status == 0, "sysctl: {}", std::io::Error::last_os_error());
    ensure!(size <= data.len(), "argument buffer exceeded limit");
    data.truncate(size);
    parse_arguments(&data)
}

fn parse_arguments(data: &[u8]) -> Result<Vec<String>> {
    ensure!(data.len() >= 4, "truncated argument count");
    let argc = i32::from_ne_bytes(data[..4].try_into()?);
    ensure!((1..=4096).contains(&argc), "invalid argument count");
    let mut rest = &data[4..];
    // Kernel layout: argc, executable path, NUL padding, argv, then environment.
    let end = rest
        .iter()
        .position(|b| *b == 0)
        .context("missing executable terminator")?;
    rest = &rest[end + 1..];
    while rest.first() == Some(&0) {
        rest = &rest[1..];
    }
    let mut args = Vec::new();
    for _ in 0..argc {
        let end = rest
            .iter()
            .position(|b| *b == 0)
            .context("truncated argv")?;
        args.push(String::from_utf8(rest[..end].to_vec()).context("non-UTF-8 argv")?);
        rest = &rest[end + 1..];
    }
    // Do not decode or retain any trailing environment entries.
    Ok(args)
}

fn bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(std::fs::metadata(path)?.is_file(), "not a regular file");
    let file = File::open(path)?;
    ensure!(file.metadata()?.is_file(), "not a regular file");
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "file exceeds {limit} bytes");
    Ok(bytes)
}

fn applications(executable: &Path, notes: &mut Vec<String>) -> Vec<ApplicationInfo> {
    let mut apps = Vec::new();
    for path in executable
        .ancestors()
        .take(64)
        .filter(|p| p.extension().is_some_and(|e| e == "app"))
        .take(8)
    {
        let plist = path.join("Contents/Info.plist");
        let result = (|| -> Result<ApplicationInfo> {
            let bytes = bounded_file(&plist, 1024 * 1024)?;
            let value = plist::Value::from_reader(std::io::Cursor::new(bytes))?;
            let dict = value
                .as_dictionary()
                .context("Info.plist is not a dictionary")?;
            let text = |key| {
                dict.get(key)
                    .and_then(plist::Value::as_string)
                    .map(str::to_owned)
            };
            Ok(ApplicationInfo {
                source: "containing .app/Contents/Info.plist (filesystem metadata, not a running-window association)".into(),
                bundle_path: path.to_string_lossy().into_owned(),
                identifier: text("CFBundleIdentifier"),
                name: text("CFBundleDisplayName").or_else(|| text("CFBundleName")),
                version: text("CFBundleShortVersionString"), build: text("CFBundleVersion"),
                executable: text("CFBundleExecutable"), icon_file: text("CFBundleIconFile"),
            })
        })();
        match result {
            Ok(app) => apps.push(app),
            Err(error) => notes.push(format!("bundle {}: {error:#}", path.display())),
        }
    }
    apps
}

fn signing(pid: i32) -> Result<CodeSigningInfo> {
    let mut attrs = GuestAttributes::new();
    attrs.set_pid(pid);
    let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE)?;
    let mut raw = std::ptr::null();
    // SAFETY: valid SecCode and writable output pointer. Copy returns ownership.
    let status =
        unsafe { SecCodeCopySigningInformation(code.as_concrete_TypeRef(), 1 << 1, &mut raw) };
    ensure!(
        status == 0 && !raw.is_null(),
        "SecCodeCopySigningInformation OSStatus {status}"
    );
    let dict: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    let get = |key| {
        dict.find(unsafe { CFString::wrap_under_get_rule(key) })
            .map(|v| (*v).clone())
    };
    let text = |key| {
        get(key)
            .and_then(|v| v.downcast::<CFString>())
            .map(|s| s.to_string())
    };
    // Dynamic identity validation; no custom requirement or revocation flags.
    let validation_status = unsafe {
        SecCodeCheckValidity(
            code.as_concrete_TypeRef(),
            Flags::NONE.bits(),
            std::ptr::null_mut(),
        )
    };
    let flags = get(unsafe { kSecCodeInfoFlags })
        .and_then(|v| v.downcast::<CFNumber>())
        .and_then(|v| v.to_i64());
    let certificate_subjects = get(unsafe { kSecCodeInfoCertificates })
        .and_then(|value| value.downcast::<CFArray>())
        .map(|array| {
            array
                .iter()
                .take(16)
                .filter_map(|value| {
                    // Security.framework's certificate array contains CF objects.
                    unsafe { CFType::wrap_under_get_rule(*value) }.downcast::<SecCertificate>()
                })
                .map(|cert| cert.subject_summary())
                .collect()
        })
        .unwrap_or_default();
    Ok(CodeSigningInfo {
        source: "Security.framework dynamic code selected by observed PID; default dynamic identity validation, not notarization or app intent".into(),
        identifier: text(unsafe { kSecCodeInfoIdentifier }),
        team_identifier: text(unsafe { kSecCodeInfoTeamIdentifier }),
        format: text(unsafe { kSecCodeInfoFormat }),
        flags,
        ad_hoc: flags.map(|flags| flags & 2 != 0),
        hardened_runtime: flags.map(|flags| flags & 0x10000 != 0),
        certificate_subjects,
        cdhash_base64: get(unsafe { kSecCodeInfoUnique }).and_then(|v| v.downcast::<CFData>()).map(|v| STANDARD.encode(v.bytes())),
        validation_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_parser_stops_before_environment_and_preserves_empty_arguments() {
        let mut bytes = 3i32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(b"/usr/bin/git\0\0\0git\0\0fetch\0TOKEN=secret\0");
        assert_eq!(parse_arguments(&bytes).unwrap(), ["git", "", "fetch"]);
        for length in 0..4 {
            assert!(parse_arguments(&bytes[..length]).is_err());
        }
        let mut invalid = 4097i32.to_ne_bytes().to_vec();
        invalid.extend_from_slice(b"/bin/test\0test\0");
        assert!(parse_arguments(&invalid).is_err());
        assert!(
            parse_arguments(&bytes[..bytes.iter().position(|b| *b == b'T').unwrap() - 1]).is_err()
        );
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn interprets_git_directory_overrides_without_running_git() {
        let parsed = interpret(
            "/usr/bin/git",
            &argv(&[
                "git",
                "-C",
                "projects",
                "-C",
                "repo",
                "-c",
                "credential.helper=secret",
                "fetch",
                "origin",
            ]),
            Some("/home/test"),
        )
        .unwrap();
        assert_eq!(parsed.subcommand.as_deref(), Some("fetch"));
        assert_eq!(
            parsed.effective_directory_candidate.as_deref(),
            Some("/home/test/projects/repo")
        );
        assert!(!serde_json::to_string(&parsed).unwrap().contains("secret"));
        let parsed = interpret(
            "/usr/bin/git",
            &argv(&["git", "--git-dir=/gitdir", "--work-tree", "/work", "status"]),
            Some("/home/test"),
        )
        .unwrap();
        assert_eq!(parsed.git_directory_argument.as_deref(), Some("/gitdir"));
        assert_eq!(parsed.work_tree_argument.as_deref(), Some("/work"));
        assert!(interpret("/usr/bin/git", &argv(&["git", "-C"]), None).is_none());
    }

    #[test]
    fn ssh_flags_are_not_mistaken_for_destinations() {
        let parsed = interpret(
            "/usr/bin/ssh",
            &argv(&[
                "ssh",
                "-vvT",
                "-o",
                "ProxyCommand=secret",
                "-p2222",
                "-l",
                "git",
                "github-alias",
                "git-upload-pack repo",
            ]),
            None,
        )
        .unwrap();
        assert_eq!(parsed.destination_argument.as_deref(), Some("github-alias"));
        assert_eq!(parsed.username_argument.as_deref(), Some("git"));
        assert_eq!(parsed.port_argument.as_deref(), Some("2222"));
        assert!(!serde_json::to_string(&parsed).unwrap().contains("secret"));
        let parsed = interpret(
            "/usr/bin/ssh",
            &argv(&["ssh", "--unknown", "value", "host"]),
            None,
        )
        .unwrap();
        assert!(parsed.destination_argument.is_none());
        let parsed = interpret(
            "/usr/bin/ssh-keygen",
            &argv(&["ssh-keygen", "-Y", "sign", "-f", "key"]),
            None,
        )
        .unwrap();
        assert_eq!(parsed.subcommand.as_deref(), Some("sign"));
    }

    #[test]
    fn bundle_and_repository_observations_are_read_only_and_support_worktrees() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("Example.app");
        std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        let mut dict = plist::Dictionary::new();
        dict.insert("CFBundleIdentifier".into(), "fyi.seccy.fixture".into());
        dict.insert("CFBundleName".into(), "Fixture".into());
        dict.insert("CFBundleShortVersionString".into(), "1.2.3".into());
        plist::Value::Dictionary(dict)
            .to_file_binary(app.join("Contents/Info.plist"))
            .unwrap();
        let mut notes = Vec::new();
        let apps = applications(&app.join("Contents/MacOS/test"), &mut notes);
        assert_eq!(apps[0].identifier.as_deref(), Some("fyi.seccy.fixture"));
        assert_eq!(apps[0].version.as_deref(), Some("1.2.3"));
        assert!(notes.is_empty());
        let work = dir.path().join("worktree");
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::write(
            work.join(".git"),
            "gitdir: /another/repo/.git/worktrees/worktree\n",
        )
        .unwrap();
        assert_eq!(
            repository(&work.join("src")),
            Some(work.to_string_lossy().into_owned())
        );
    }

    #[test]
    fn native_observations_work_for_current_process() {
        let pid = std::process::id() as i32;
        let directory = cwd(pid).unwrap();
        assert_eq!(
            std::fs::canonicalize(directory).unwrap(),
            std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap()
        );
        let args = arguments(pid).unwrap();
        assert!(!args.is_empty());
        let signature = signing(pid).unwrap();
        assert!(signature.identifier.is_some());
        assert_eq!(signature.validation_status, 0);
    }
}
