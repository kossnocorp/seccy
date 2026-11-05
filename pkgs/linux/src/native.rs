use anyhow::{Context, Result, ensure};
use std::ffi::{CStr, CString, c_char, c_int};
use zeroize::Zeroizing;

unsafe extern "C" {
    fn sc_tpm_test(
        transport: *const c_char,
        operation: c_int,
        auth: *const u8,
        blob: *mut u8,
        blob_len: *mut usize,
        input: *const u8,
        output: *mut u8,
        parent_name: *mut u8,
    ) -> c_int;
    fn sc_free(value: *mut c_char);
    fn sc_devices(out: *mut *mut c_char) -> c_int;
    fn sc_secret(
        vault: *const c_char,
        key: *const c_char,
        value: *const c_char,
        operation: c_int,
        out: *mut *mut c_char,
    ) -> c_int;
    fn sc_fido(
        device: *const c_char,
        rp: *const c_char,
        user: *const u8,
        challenge: *const u8,
        salt: *const u8,
        id: *const u8,
        id_len: usize,
        public: *const u8,
        details: *const c_char,
        new_id: *mut u8,
        new_id_len: *mut usize,
        new_public: *mut u8,
        secret: *mut u8,
    ) -> c_int;
    fn sc_tpm(
        operation: c_int,
        auth: *const u8,
        blob: *mut u8,
        blob_len: *mut usize,
        input: *const u8,
        output: *mut u8,
        parent_name: *mut u8,
    ) -> c_int;
}

fn take(value: *mut c_char) -> Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }
    // Native strings are allocated with GLib and released with the matching API.
    let result = unsafe { CStr::from_ptr(value) }.to_str().map(str::to_owned);
    unsafe { sc_free(value) };
    Ok(Some(
        result.context("native service returned invalid UTF-8")?,
    ))
}

pub fn devices() -> Result<Vec<String>> {
    let mut output = std::ptr::null_mut();
    let status = unsafe { sc_devices(&mut output) };
    let output = take(output)?.unwrap_or_default();
    ensure!(status == 0, "cannot enumerate FIDO authenticators");
    Ok(output.lines().map(str::to_owned).collect())
}

pub fn secret(vault: &str, key: &str, value: Option<&str>, remove: bool) -> Result<Option<String>> {
    let vault = CString::new(vault)?;
    let key = CString::new(key)?;
    let value = CString::new(value.unwrap_or_default())?;
    let operation = if remove {
        2
    } else if value.as_bytes().is_empty() {
        0
    } else {
        1
    };
    let mut output = std::ptr::null_mut();
    let status = unsafe {
        sc_secret(
            vault.as_ptr(),
            key.as_ptr(),
            value.as_ptr(),
            operation,
            &mut output,
        )
    };
    let output = take(output)?;
    ensure!(
        status == 0,
        "Secret Service unavailable, locked, or operation cancelled"
    );
    Ok(output)
}

pub struct Credential {
    pub id: Vec<u8>,
    pub public: Vec<u8>,
    pub secret: Zeroizing<[u8; 32]>,
}

pub fn fido(
    device: &str,
    user: &[u8; 32],
    challenge: &[u8; 32],
    salt: &[u8; 32],
    credential: Option<(&[u8], &[u8])>,
    details: &str,
) -> Result<Credential> {
    let path = CString::new(device)?;
    let rp = c"seccy.fyi";
    let details = CString::new(details)?;
    let mut id = vec![0; 4096];
    let mut id_len = id.len();
    let mut public = vec![0; 64];
    let mut secret = Zeroizing::new([0; 32]);
    if let Some((id, public)) = credential {
        ensure!(
            !id.is_empty() && id.len() <= 4096 && public.len() == 64,
            "invalid FIDO enrollment"
        );
    }
    let status = unsafe {
        sc_fido(
            path.as_ptr(),
            rp.as_ptr(),
            user.as_ptr(),
            challenge.as_ptr(),
            salt.as_ptr(),
            credential.map_or(std::ptr::null(), |c| c.0.as_ptr()),
            credential.map_or(0, |c| c.0.len()),
            credential.map_or(std::ptr::null(), |c| c.1.as_ptr()),
            details.as_ptr(),
            id.as_mut_ptr(),
            &mut id_len,
            public.as_mut_ptr(),
            secret.as_mut_ptr(),
        )
    };
    ensure!(
        status == 0,
        "FIDO authorization failed: cancelled, wrong/missing key, unsupported hmac-secret/UV protection, or verification failed"
    );
    id.truncate(id_len);
    Ok(Credential { id, public, secret })
}

pub fn tpm(
    operation: i32,
    auth: &[u8; 32],
    blob: &mut Vec<u8>,
    input: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(not(test))]
    {
        crate::broker::request(operation, auth, blob, input)
    }
    #[cfg(test)]
    {
        tpm_direct(operation, auth, blob, input)
    }
}

pub(crate) fn tpm_direct(
    operation: i32,
    auth: &[u8; 32],
    blob: &mut Vec<u8>,
    input: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let output_size = match operation {
        0 => 0,
        1 => 65,
        2 => 64,
        3 => 32,
        _ => anyhow::bail!("invalid TPM operation"),
    };
    ensure!(
        operation != 2 || input.len() == 32,
        "invalid signing digest"
    );
    ensure!(operation != 3 || input.len() == 65, "invalid ECDH point");
    if operation == 1 {
        blob.resize(4096, 0);
    }
    let mut length = blob.len();
    let mut output = vec![0; output_size];
    let mut parent = vec![0; 34];
    #[cfg(test)]
    let transport = std::env::var("SECCY_TEST_TCTI")
        .ok()
        .map(CString::new)
        .transpose()?;
    #[cfg(not(test))]
    let transport: Option<CString> = None;
    let status = unsafe {
        if let Some(transport) = transport {
            sc_tpm_test(
                transport.as_ptr(),
                operation,
                auth.as_ptr(),
                blob.as_mut_ptr(),
                &mut length,
                input.as_ptr(),
                output.as_mut_ptr(),
                parent.as_mut_ptr(),
            )
        } else {
            sc_tpm(
                operation,
                auth.as_ptr(),
                blob.as_mut_ptr(),
                &mut length,
                input.as_ptr(),
                output.as_mut_ptr(),
                parent.as_mut_ptr(),
            )
        }
    };
    ensure!(
        status == 0,
        "TPM operation failed; check /dev/tpmrm0 access, TPM ownership, capacity, and key authorization"
    );
    blob.truncate(length);
    Ok((output, parent))
}
