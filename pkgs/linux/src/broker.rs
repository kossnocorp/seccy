//! Fixed, bounded TPM operations over a kernel-authenticated local socket.
//! No command execution, arbitrary TPM commands, UI, or user-selected paths.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

const SOCKET: &str = "/run/seccy-tpm/socket";
const STATE: &str = "/var/lib/seccy-tpm";
const MAX_FRAME: usize = 24 * 1024;
const MAX_KEYS: usize = 512;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    operation: i32,
    auth: [u8; 32],
    blob: Vec<u8>,
    input: Vec<u8>,
}
impl Drop for Request {
    fn drop(&mut self) {
        self.auth.zeroize();
        self.blob.zeroize();
        self.input.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    blob: Vec<u8>,
    output: Vec<u8>,
    parent: Vec<u8>,
}
impl Drop for Response {
    fn drop(&mut self) {
        self.blob.zeroize();
        self.output.zeroize();
    }
}

fn frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(
        (1..=MAX_FRAME).contains(&length),
        "invalid broker frame length"
    );
    let mut bytes = Zeroizing::new(vec![0; length]);
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn send(stream: &mut UnixStream, value: &impl Serialize) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(value)?);
    ensure!(bytes.len() <= MAX_FRAME, "broker frame too large");
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}
fn peer(stream: &UnixStream) -> Result<libc::ucred> {
    let mut value: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut value as *mut libc::ucred).cast(),
                &mut size,
            )
        } == 0
            && size as usize == std::mem::size_of_val(&value),
        "cannot authenticate broker socket peer"
    );
    Ok(value)
}
fn service_uid() -> Result<u32> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 64 * 1024];
    let mut result = std::ptr::null_mut();
    ensure!(
        unsafe {
            libc::getpwnam_r(
                c"seccy-tpm".as_ptr(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        } == 0
            && !result.is_null(),
        "TPM service account missing; install the Seccy TPM system service"
    );
    Ok(entry.pw_uid)
}
fn timeout(stream: &UnixStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    Ok(())
}
fn validate(request: &Request) -> Result<()> {
    ensure!(
        request.version == 1 && request.blob.len() <= 4096 && request.input.len() <= 65,
        "invalid TPM broker request"
    );
    match request.operation {
        0 | 1 => ensure!(
            request.blob.is_empty() && request.input.is_empty(),
            "unexpected operation input"
        ),
        2 => ensure!(
            !request.blob.is_empty() && request.input.len() == 32,
            "invalid signing request"
        ),
        3 => {
            ensure!(
                !request.blob.is_empty() && request.input.len() == 65 && request.input[0] == 4,
                "invalid ECDH request"
            );
            p256::PublicKey::from_sec1_bytes(&request.input)?;
        }
        4 => ensure!(
            !request.blob.is_empty() && request.input.is_empty(),
            "invalid forget request"
        ),
        _ => anyhow::bail!("unsupported broker operation"),
    }
    Ok(())
}

pub(crate) fn request(
    operation: i32,
    auth: &[u8; 32],
    blob: &mut Vec<u8>,
    input: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let request = Request {
        version: 1,
        operation,
        auth: *auth,
        blob: blob.clone(),
        input: input.to_vec(),
    };
    validate(&request)?;
    let mut stream = UnixStream::connect(SOCKET)
        .context("Seccy TPM service unavailable; install/start seccy-tpm.service")?;
    timeout(&stream)?;
    let uid = service_uid()?;
    ensure!(
        uid != 0 && peer(&stream)?.uid == uid,
        "unexpected TPM service identity"
    );
    send(&mut stream, &request)?;
    let response: Response = serde_json::from_slice(&frame(&mut stream)?)
        .map_err(|_| anyhow::anyhow!("invalid TPM service response"))?;
    ensure!(
        response.ok,
        "TPM service rejected the operation; check key ownership, authorization, quota, and service status"
    );
    let expected = match operation {
        0 | 4 => 0,
        1 => 65,
        2 => 64,
        3 => 32,
        _ => unreachable!(),
    };
    ensure!(
        response.output.len() == expected
            && (response.parent.len() == 34 || operation == 4)
            && response.blob.len() <= 4096,
        "invalid TPM service result"
    );
    *blob = response.blob.clone();
    Ok((response.output.clone(), response.parent.clone()))
}

fn fingerprint(blob: &[u8]) -> String {
    Sha256::digest(blob)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn catalog(state: &Path, uid: u32) -> Result<BTreeSet<String>> {
    let path = state.join(format!("{uid}.json"));
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.take(128 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 128 * 1024, "broker catalog too large");
    let keys: BTreeSet<String> = serde_json::from_slice(&bytes)?;
    ensure!(
        keys.len() <= MAX_KEYS
            && keys
                .iter()
                .all(|k| k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit())),
        "invalid broker catalog"
    );
    Ok(keys)
}
fn save(state: &Path, uid: u32, keys: &BTreeSet<String>) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(state)?;
    file.write_all(&serde_json::to_vec(keys)?)?;
    file.as_file().sync_all()?;
    file.persist(state.join(format!("{uid}.json")))?;
    File::open(state)?.sync_all()?;
    Ok(())
}
fn authorize(keys: &BTreeSet<String>, request: &Request) -> Result<()> {
    if matches!(request.operation, 2 | 3) {
        ensure!(
            keys.contains(&fingerprint(&request.blob)),
            "TPM key does not belong to requesting UID"
        );
    }
    if request.operation == 1 {
        ensure!(keys.len() < MAX_KEYS, "TPM broker key quota reached");
    }
    Ok(())
}
fn execute(state: &Path, uid: u32, request: &mut Request) -> Result<Response> {
    validate(request)?;
    let mut keys = catalog(state, uid)?;
    authorize(&keys, request)?;
    if request.operation == 4 {
        keys.remove(&fingerprint(&request.blob));
        save(state, uid, &keys)?;
        return Ok(Response {
            ok: true,
            blob: Vec::new(),
            output: Vec::new(),
            parent: Vec::new(),
        });
    }
    let (output, parent) = crate::native::tpm_direct(
        request.operation,
        &request.auth,
        &mut request.blob,
        &request.input,
    )?;
    if request.operation == 1 {
        keys.insert(fingerprint(&request.blob));
        save(state, uid, &keys)?;
    }
    Ok(Response {
        ok: true,
        blob: request.blob.clone(),
        output,
        parent,
    })
}

/// Entry point for the administrator-installed, unprivileged system daemon.
pub fn serve() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == service_uid()? && unsafe { libc::geteuid() } != 0,
        "TPM service must run as the dedicated seccy-tpm account"
    );
    let state = Path::new(STATE);
    let metadata = fs::symlink_metadata(state)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "TPM service state directory must be private and owned by the service"
    );
    let lock = File::create(state.join("service.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).context("TPM service already running")?;
    match fs::remove_file(SOCKET) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o666))?;
    let operations = Arc::new(Mutex::new(()));
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let mut stream = stream?;
        if active.load(Ordering::SeqCst) >= 16 {
            continue;
        }
        let credentials = peer(&stream)?;
        if credentials.uid == service_uid()? {
            continue;
        }
        timeout(&stream)?;
        active.fetch_add(1, Ordering::SeqCst);
        let active = active.clone();
        let operations = operations.clone();
        std::thread::spawn(move || {
            let result = (|| -> Result<Response> {
                let mut request: Request = serde_json::from_slice(&frame(&mut stream)?)
                    .map_err(|_| anyhow::anyhow!("invalid request"))?;
                validate(&request)?;
                let _guard = operations
                    .lock()
                    .map_err(|_| anyhow::anyhow!("TPM service lock poisoned"))?;
                execute(Path::new(STATE), credentials.uid, &mut request)
            })();
            // Never log request bytes, authorization values, or ECDH outputs.
            let response = result.unwrap_or(Response {
                ok: false,
                blob: Vec::new(),
                output: Vec::new(),
                parent: Vec::new(),
            });
            let _ = send(&mut stream, &response);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires TPM or isolated emulator"]
    fn physical_tpm_signing_and_ecdh_broker_ownership() {
        use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
        let dir = tempfile::tempdir().unwrap();
        let mut request = Request {
            version: 1,
            operation: 1,
            auth: [42; 32],
            blob: Vec::new(),
            input: Vec::new(),
        };
        let created = execute(dir.path(), 1000, &mut request).unwrap();
        request.operation = 2;
        request.input = Sha256::digest(b"broker ownership test").to_vec();
        assert!(execute(dir.path(), 1001, &mut request).is_err());
        let signed = execute(dir.path(), 1000, &mut request).unwrap();
        VerifyingKey::from_sec1_bytes(&created.output)
            .unwrap()
            .verify_prehash(
                &request.input,
                &Signature::from_slice(&signed.output).unwrap(),
            )
            .unwrap();
        request.auth = [43; 32];
        assert!(execute(dir.path(), 1000, &mut request).is_err());
        request.operation = 4;
        request.input.clear();
        execute(dir.path(), 1001, &mut request).unwrap();
        assert_eq!(catalog(dir.path(), 1000).unwrap().len(), 1);
        execute(dir.path(), 1000, &mut request).unwrap();
        execute(dir.path(), 1000, &mut request).unwrap();
        assert!(catalog(dir.path(), 1000).unwrap().is_empty());
        request.operation = 2;
        request.input = vec![0; 32];
        assert!(execute(dir.path(), 1000, &mut request).is_err());
    }
    #[test]
    fn ownership_and_quota_are_enforced_before_tpm_access() {
        let dir = tempfile::tempdir().unwrap();
        let keys = [fingerprint(b"alice-key")].into_iter().collect();
        save(dir.path(), 1000, &keys).unwrap();
        let request = Request {
            version: 1,
            operation: 2,
            auth: [0; 32],
            blob: b"alice-key".to_vec(),
            input: vec![0; 32],
        };
        validate(&request).unwrap();
        assert!(authorize(&catalog(dir.path(), 1000).unwrap(), &request).is_ok());
        assert!(authorize(&catalog(dir.path(), 1001).unwrap(), &request).is_err());
        let full = (0..MAX_KEYS)
            .map(|i| fingerprint(&i.to_be_bytes()))
            .collect();
        let create = Request {
            version: 1,
            operation: 1,
            auth: [0; 32],
            blob: Vec::new(),
            input: Vec::new(),
        };
        assert!(authorize(&full, &create).is_err());
    }
    #[test]
    fn rejects_unknown_commands_and_malformed_frames() {
        let request = Request {
            version: 1,
            operation: 99,
            auth: [0; 32],
            blob: Vec::new(),
            input: Vec::new(),
        };
        assert!(validate(&request).is_err());
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(frame(&mut server).is_err());
        assert_eq!(peer(&client).unwrap().uid, unsafe { libc::geteuid() });
    }
}
