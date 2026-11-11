//! Multi-recipient secrets. Public recipients are independent of local key inventory.
//! This is a Seccy format, not an age-compatible wire format.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub const MAX_SECRET: usize = 64 * 1024;
pub const MAX_ENVELOPE: usize = 160 * 1024;
pub const MAX_RECIPIENTS: usize = 32;
const PREFIX: &str = "seccy:secrets:v1:";
const RECIPIENT: &str = "seccy-se1:";

pub fn recipient(point: &[u8]) -> Result<String> {
    crate::Identity::new("recipient", crate::Mode::Prompt, point)?;
    Ok(format!("{RECIPIENT}{}", B64.encode(point)))
}
pub fn point(value: &str) -> Result<Vec<u8>> {
    ensure!(value.len() <= 128, "recipient is too long");
    let bytes = B64
        .decode(
            value.strip_prefix(RECIPIENT).context(
                "expected a seccy-se1 public recipient, not a fingerprint or private key",
            )?,
        )
        .map_err(|_| anyhow::anyhow!("invalid public recipient encoding"))?;
    ensure!(recipient(&bytes)? == value, "noncanonical public recipient");
    Ok(bytes)
}
pub fn fingerprint(value: &str) -> Result<String> {
    Ok(crate::Identity::new("recipient", crate::Mode::Prompt, &point(value)?)?.fingerprint)
}
pub fn from_identity(identity: &crate::Identity) -> Result<String> {
    // Compare the entire canonical SSH blob; never accept an arbitrary trailing point.
    let bytes = identity
        .blob
        .get(identity.blob.len().saturating_sub(65)..)
        .context("invalid public key")?;
    let canonical = crate::Identity::new("recipient", crate::Mode::Prompt, bytes)?;
    ensure!(
        canonical.blob == identity.blob,
        "invalid P-256 SSH public key"
    );
    recipient(bytes)
}
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub name: String,
    pub wrapped: BTreeMap<String, String>,
    nonce: String,
    ciphertext: String,
}
impl Envelope {
    fn aad(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            PREFIX,
            &self.name,
            &self.wrapped,
            &self.nonce,
        ))?)
    }
    pub fn parse(value: &str, name: &str) -> Result<Self> {
        ensure!(
            value.len() <= MAX_ENVELOPE,
            "secret envelope exceeds size limit"
        );
        let data = B64
            .decode(
                value
                    .strip_prefix(PREFIX)
                    .context("unsupported managed secret format")?,
            )
            .map_err(|_| anyhow::anyhow!("invalid secret envelope"))?;
        let envelope: Self = serde_json::from_slice(&data)
            .map_err(|_| anyhow::anyhow!("invalid secret envelope"))?;
        ensure!(
            valid_name(name) && envelope.name == name,
            "secret name does not match authenticated envelope"
        );
        ensure!(
            !envelope.wrapped.is_empty() && envelope.wrapped.len() <= MAX_RECIPIENTS,
            "invalid recipient count"
        );
        for (id, wrap) in &envelope.wrapped {
            ensure!(
                id.starts_with("SHA256:") && id.len() == 50 && wrap.len() <= 4096,
                "invalid recipient stanza"
            );
        }
        ensure!(
            B64.decode(&envelope.nonce)?.len() == 12,
            "invalid payload nonce"
        );
        let size = B64.decode(&envelope.ciphertext)?.len();
        ensure!(
            (16..=MAX_SECRET + 16).contains(&size),
            "invalid payload size"
        );
        Ok(envelope)
    }
    pub fn decrypt(&self, key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(key.len() == 32, "invalid unwrapped file key");
        let nonce: [u8; 12] = B64
            .decode(&self.nonce)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid nonce"))?;
        let clear = Aes256Gcm::new_from_slice(key)?
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &B64.decode(&self.ciphertext)?,
                    aad: &self.aad()?,
                },
            )
            .map_err(|_| anyhow::anyhow!("secret authentication failed"))?;
        Ok(Zeroizing::new(clear))
    }
    pub fn matches(&self, recipients: &[String]) -> Result<()> {
        let expected = recipients
            .iter()
            .map(|r| fingerprint(r))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            expected == self.wrapped.keys().cloned().collect(),
            "configured recipients do not match ciphertext; run secrets reencrypt to update recipients"
        );
        Ok(())
    }
}

pub fn encrypt(
    name: &str,
    plaintext: &[u8],
    recipients: &[String],
    mut wrap: impl FnMut(&str, &[u8]) -> Result<String>,
) -> Result<String> {
    ensure!(
        valid_name(name),
        "invalid secret name; use an environment variable name"
    );
    ensure!(plaintext.len() <= MAX_SECRET, "secret exceeds 64 KiB");
    ensure!(
        !recipients.is_empty() && recipients.len() <= MAX_RECIPIENTS,
        "select 1–32 recipients"
    );
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut wrapped = BTreeMap::new();
    for r in recipients {
        let id = fingerprint(r)?;
        ensure!(!wrapped.contains_key(&id), "duplicate recipient public key");
        wrapped.insert(id, wrap(r, key.as_ref())?);
    }
    let mut envelope = Envelope {
        name: name.into(),
        wrapped,
        nonce: B64.encode(nonce),
        ciphertext: String::new(),
    };
    let ciphertext = Aes256Gcm::new_from_slice(key.as_ref())?
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &envelope.aad()?,
            },
        )
        .map_err(|_| anyhow::anyhow!("secret encryption failed"))?;
    envelope.ciphertext = B64.encode(ciphertext);
    let value = format!("{PREFIX}{}", B64.encode(serde_json::to_vec(&envelope)?));
    ensure!(
        value.len() <= MAX_ENVELOPE,
        "secret envelope exceeds size limit"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn public() -> String {
        let point = p256::SecretKey::from_slice(&[1; 32]).unwrap().public_key();
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        recipient(point.to_encoded_point(false).as_bytes()).unwrap()
    }
    #[test]
    fn binds_name_recipient_stanzas_nonce_and_payload() {
        let r = public();
        let mut key = Vec::new();
        let value = encrypt(
            "TOKEN",
            b"\0binary\xff\n",
            std::slice::from_ref(&r),
            |_, k| {
                key = k.to_vec();
                Ok("test-only-key-wrap".into())
            },
        )
        .unwrap();
        let e = Envelope::parse(&value, "TOKEN").unwrap();
        assert_eq!(&*e.decrypt(&key).unwrap(), b"\0binary\xff\n");
        assert!(Envelope::parse(&value, "OTHER").is_err());
        for field in ["name", "wrapped", "nonce", "ciphertext"] {
            let mut e = Envelope::parse(&value, "TOKEN").unwrap();
            match field {
                "name" => e.name = "OTHER".into(),
                "wrapped" => {
                    e.wrapped
                        .insert("another-recipient".into(), "changed".into());
                }
                "nonce" => e.nonce = B64.encode([0; 12]),
                _ => {
                    let mut c = B64.decode(&e.ciphertext).unwrap();
                    c[0] ^= 1;
                    e.ciphertext = B64.encode(c);
                }
            }
            assert!(e.decrypt(&key).is_err(), "{field}");
        }
        assert!(e.decrypt(&[0; 32]).is_err());
        assert!(encrypt("TOKEN", b"x", &[r.clone(), r], |_, _| Ok("x".into())).is_err());
        assert!(encrypt("1BAD", b"x", &[public()], |_, _| Ok("x".into())).is_err());
        assert!(
            encrypt("TOKEN", &vec![0; MAX_SECRET + 1], &[public()], |_, _| Ok(
                "x".into()
            ))
            .is_err()
        );
        assert!(point("SHA256:fingerprint-is-not-a-public-key").is_err());
        assert!(point(&format!("{RECIPIENT}{}", B64.encode([0; 65]))).is_err());
    }
}
