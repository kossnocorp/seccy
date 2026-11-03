//! Bounded, strict subset of the SSH agent protocol. Mutation and forwarding
//! extensions are deliberately unsupported.
use crate::{Caller, Identity, KeyStore};
use anyhow::{Context, Result, bail, ensure};
use std::io::{Read, Write};

pub const ALGORITHM: &[u8] = b"ecdsa-sha2-nistp256";
pub const MAX_FRAME: usize = 256 * 1024;
pub const FAILURE: u8 = 5;

pub fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.0.len(), "truncated agent request");
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }
    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn end(&self) -> Result<()> {
        ensure!(self.0.is_empty(), "trailing agent request bytes");
        Ok(())
    }
}

pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut size = [0; 4];
    // EOF is clean only before the first byte, not midway through a frame.
    if reader.read(&mut size[..1])? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut size[1..])?;
    let len = u32::from_be_bytes(size) as usize;
    ensure!((1..=MAX_FRAME).contains(&len), "invalid agent frame length");
    let mut data = vec![0; len];
    reader.read_exact(&mut data)?;
    Ok(Some(data))
}

pub fn write_frame(writer: &mut impl Write, data: &[u8]) -> Result<()> {
    ensure!(data.len() <= MAX_FRAME, "agent response too large");
    writer.write_all(&(data.len() as u32).to_be_bytes())?;
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

pub fn respond(
    store: &impl KeyStore,
    keys: &[Identity],
    caller: &Caller,
    request: &[u8],
) -> Result<Vec<u8>> {
    ensure!(request.len() <= MAX_FRAME, "agent request too large");
    let mut r = Reader(request);
    match r.take(1)?[0] {
        11 => {
            r.end()?;
            let mut out = vec![12];
            out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
            for key in keys {
                string(&mut out, &key.blob);
                string(&mut out, key.name.as_bytes());
            }
            Ok(out)
        }
        13 => {
            let blob = r.string()?;
            let message = r.string()?;
            ensure!(r.u32()? == 0, "unsupported signature flags");
            r.end()?;
            let key = keys
                .iter()
                .find(|k| k.blob == blob)
                .context("unknown agent key")?;
            let der = store.sign(key, message, caller)?;
            let signature =
                p256::ecdsa::Signature::from_der(&der).context("invalid ECDSA signature")?;
            let bytes = signature.to_bytes();
            let mut scalars = Vec::new();
            for scalar in bytes.chunks_exact(32) {
                let first = scalar.iter().position(|b| *b != 0).unwrap_or(31);
                let scalar = &scalar[first..];
                let mut mpint = Vec::new();
                if scalar[0] & 0x80 != 0 {
                    mpint.push(0);
                }
                mpint.extend_from_slice(scalar);
                string(&mut scalars, &mpint);
            }
            let mut signature = Vec::new();
            string(&mut signature, ALGORITHM);
            string(&mut signature, &scalars);
            let mut out = vec![14];
            string(&mut out, &signature);
            Ok(out)
        }
        27 => Ok(vec![28]), // SSH_AGENT_EXTENSION_FAILURE
        _ => bail!("unsupported agent request"),
    }
}
