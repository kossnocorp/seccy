//! Provider selection and policy configuration. Parsing never performs hardware operations.
use crate::Mode;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Github {
    Signing,
    Auth,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Use {
    SshAuth,
    SshSign,
    Secrets,
    OpenpgpSign,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Forge {
    Github,
    Gitlab,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Many<T>(pub Vec<T>);
impl<'de, T: Deserialize<'de> + Ord> Deserialize<'de> for Many<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Input<T> {
            Many(Vec<T>),
            One(T),
        }
        let values = match Input::deserialize(d)? {
            Input::One(v) => vec![v],
            Input::Many(v) => v,
        };
        if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
            return Err(serde::de::Error::custom("duplicate value"));
        }
        Ok(Self(values))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Selector {
    Named(String),
    Map(SelectMap),
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectMap {
    pub os: Option<BTreeMap<String, String>>,
    pub host: Option<BTreeMap<String, String>>,
}
impl Selector {
    fn names(&self) -> Result<Vec<&str>> {
        match self {
            Self::Named(n) => Ok(vec![n]),
            Self::Map(m) => {
                ensure!(
                    m.os.is_some() != m.host.is_some(),
                    "provider selector requires exactly one of os or host"
                );
                if let Some(os) = &m.os {
                    ensure!(
                        os.keys().all(|s| matches!(s.as_str(), "macos" | "linux")),
                        "unknown provider OS ID"
                    );
                }
                Ok(m.os
                    .as_ref()
                    .or(m.host.as_ref())
                    .unwrap()
                    .values()
                    .map(String::as_str)
                    .collect())
            }
        }
    }
    fn select<'a>(&'a self, os: &str, host: &str) -> Option<&'a str> {
        match self {
            Self::Named(n) => Some(n),
            Self::Map(m) => {
                m.os.as_ref()
                    .and_then(|v| v.get(os))
                    .or_else(|| m.host.as_ref().and_then(|v| v.get(host)))
                    .map(String::as_str)
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub kind: String,
    pub auth: Option<String>,
    pub mode: Option<Mode>,
    pub verify: Option<String>,
    pub slot: Option<String>,
    pub algorithm: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub kind: String,
    pub name: Option<String>,
    pub bind: Option<String>,
    pub verify: Option<String>,
    pub slot: Option<String>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub provider: Option<Selector>,
    pub kind: Option<String>,
    pub mode: Option<Mode>,
    pub auth: Option<String>,
    pub verify: Option<String>,
    pub slot: Option<String>,
    pub algorithm: Option<String>,
    #[serde(rename = "use")]
    pub uses: Option<Many<Use>>,
    pub forge: Option<Many<Forge>>,
    pub github: Option<Github>,
    pub gitlab: Option<Many<Github>>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub bind: Option<String>,
}
impl KeyConfig {
    pub fn github_roles(&self) -> Vec<Github> {
        if self
            .forge
            .as_ref()
            .is_some_and(|f| f.0.contains(&Forge::Github))
        {
            self.uses
                .as_ref()
                .into_iter()
                .flat_map(|u| u.0.iter())
                .filter_map(|u| match u {
                    Use::SshAuth => Some(Github::Auth),
                    Use::SshSign => Some(Github::Signing),
                    _ => None,
                })
                .collect()
        } else {
            self.github.into_iter().collect()
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub log_level: Option<String>,
    pub email: Option<String>,
    pub provider: Option<Selector>,
    pub mode: Option<Mode>,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub providers: BTreeMap<String, Provider>,
    #[serde(default)]
    pub auth: BTreeMap<String, Auth>,
    #[serde(default)]
    pub keys: BTreeMap<String, KeyConfig>,
    #[serde(skip)]
    pub sources: Vec<PathBuf>,
    #[serde(skip)]
    pub provenance: BTreeMap<String, PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resolved {
    pub kind: String,
    pub mode: Mode,
    pub auth: Option<String>,
    pub verify: Option<String>,
    pub slot: Option<String>,
    pub algorithm: Option<String>,
}
#[derive(Serialize)]
pub struct Capability {
    pub kind: &'static str,
    pub status: &'static str,
    pub platform: Option<&'static str>,
    pub preview: bool,
    pub managed_secrets: bool,
}
pub fn catalog() -> Vec<Capability> {
    [
        "secure-enclave",
        "tpm-fido2-hmac",
        "tpm-fido2-broker",
        "tpm-piv",
        "tpm-fido2-preview-sign",
        "fido2-ssh",
        "piv",
        "openpgp",
        "fido2-preview-sign",
        "fido2-hmac-secret",
        "fido2-wrapped-key",
    ]
    .into_iter()
    .map(|kind| Capability {
        kind,
        status: match kind {
            "secure-enclave" | "tpm-fido2-hmac" => "implemented",
            "fido2-hmac-secret" | "fido2-wrapped-key" => "candidate",
            _ => "planned",
        },
        platform: match kind {
            "secure-enclave" => Some("macos"),
            "tpm-fido2-hmac" => Some("linux"),
            _ => None,
        },
        preview: kind.contains("preview-sign"),
        managed_secrets: kind == "secure-enclave",
    })
    .collect()
}
fn known(kind: &str) -> bool {
    catalog().iter().any(|c| c.kind == kind)
}
pub fn platform_kind() -> &'static str {
    if cfg!(target_os = "macos") {
        "secure-enclave"
    } else {
        "tpm-fido2-hmac"
    }
}
pub fn hostname() -> Result<String> {
    // OS hostname, no DNS resolution or environment-controlled identity.
    let mut name = [0u8; 256];
    ensure!(
        unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) } == 0,
        "cannot read hostname"
    );
    let end = name
        .iter()
        .position(|b| *b == 0)
        .context("hostname too long")?;
    Ok(std::str::from_utf8(&name[..end])?.to_owned())
}
pub fn valid_handle(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
pub(crate) fn validate_email(email: Option<&str>, field: &str) -> Result<()> {
    if let Some(email) = email {
        ensure!(
            !email.is_empty() && !email.chars().any(|c| c.is_whitespace() || c.is_control()),
            "{field} must be nonempty and contain no whitespace or control characters"
        );
    }
    Ok(())
}
fn display_name(name: Option<&str>) -> Result<()> {
    if let Some(n) = name {
        ensure!(
            !n.is_empty() && n.len() <= 160 && !n.chars().any(char::is_control),
            "invalid display name"
        );
    }
    Ok(())
}
impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let c: Self = toml::from_str(text).context("invalid configuration TOML")?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        validate_email(self.email.as_deref(), "email")?;
        ensure!(
            self.keys.len() <= 128 && self.providers.len() <= 128 && self.auth.len() <= 128,
            "at most 128 keys, providers or auth records are supported"
        );
        let check_selector = |s: &Selector| -> Result<()> {
            for n in s.names()? {
                ensure!(
                    n == "default" || known(n) || self.providers.contains_key(n),
                    "unknown provider {n}"
                );
            }
            Ok(())
        };
        if let Some(s) = &self.provider {
            check_selector(s)?;
        }
        for (name, p) in &self.providers {
            ensure!(
                valid_handle(name) && !known(name) && name != "default",
                "invalid or reserved provider name {name}"
            );
            self.validate_parameters(p)?;
        }
        for (name, a) in &self.auth {
            ensure!(valid_handle(name), "invalid auth handle {name}");
            ensure!(
                matches!(a.kind.as_str(), "fido2" | "piv" | "fido2-preview-sign"),
                "unsupported auth kind {}",
                a.kind
            );
            display_name(a.name.as_deref())?;
            if a.kind != "piv" {
                ensure!(
                    a.verify.is_none() && a.slot.is_none(),
                    "auth {name}: verify/slot require PIV"
                );
            }
            if let Some(v) = &a.verify {
                ensure!(
                    matches!(v.as_str(), "pin-touch" | "biometric-or-pin-touch"),
                    "unsupported verification policy {v}"
                );
            }
            if let Some(b) = &a.bind {
                ensure!(!b.is_empty() && b.len() <= 16384, "invalid auth binding");
            }
        }
        for (name, k) in &self.keys {
            ensure!(
                valid_handle(name),
                "key name must contain 1–64 ASCII letters, digits, underscores or hyphens: {name}"
            );
            validate_email(k.email.as_deref(), &format!("keys.{name}.email"))?;
            display_name(k.name.as_deref())?;
            ensure!(
                !(k.kind.is_some() && k.provider.is_some()),
                "key {name}: kind and provider are mutually exclusive"
            );
            if let Some(s) = &k.provider {
                check_selector(s)?;
            }
            if let Some(kind) = &k.kind {
                ensure!(known(kind), "unknown provider kind {kind}");
            }
            if let Some(u) = &k.uses {
                ensure!(!u.0.is_empty(), "key {name}: use must not be empty");
            }
            if let Some(f) = &k.forge {
                ensure!(
                    k.github.is_none() && k.gitlab.is_none(),
                    "key {name}: forge conflicts with deprecated github/gitlab fields"
                );
                ensure!(k.uses.is_some(), "key {name}: forge requires explicit use");
                ensure!(
                    f.0.is_empty()
                        || k.uses
                            .as_ref()
                            .unwrap()
                            .0
                            .iter()
                            .any(|u| *u != Use::Secrets),
                    "key {name}: forge has no publishable role"
                );
            }
            if let Some(g) = &k.gitlab {
                ensure!(
                    !g.0.is_empty(),
                    "key {name}: gitlab roles must not be empty"
                );
            }
            if let Some(u) = &k.uses {
                for role in k
                    .github
                    .iter()
                    .chain(k.gitlab.iter().flat_map(|g| g.0.iter()))
                {
                    ensure!(
                        u.0.contains(&match role {
                            Github::Auth => Use::SshAuth,
                            Github::Signing => Use::SshSign,
                        }),
                        "key {name}: deprecated forge role is not permitted by use"
                    );
                }
            }
            if let Some(b) = &k.bind {
                ensure!(!b.is_empty() && b.len() <= 16384, "invalid key binding");
            }
            // Validate parameters for every concrete possible selection, not just this host.
            let names = if let Some(kind) = &k.kind {
                vec![kind.as_str()]
            } else if let Some(s) = k.provider.as_ref().or(self.provider.as_ref()) {
                s.names()?
            } else {
                vec!["default"]
            };
            for selected in names {
                let selected = if selected == "default" {
                    "secure-enclave"
                } else {
                    selected
                };
                let p = self.parameters(k, selected);
                self.validate_parameters(&p)?;
            }
        }
        Ok(())
    }
    fn parameters(&self, k: &KeyConfig, selected: &str) -> Provider {
        let p = self.providers.get(selected).cloned().unwrap_or(Provider {
            kind: selected.into(),
            ..Provider::default()
        });
        Provider {
            kind: p.kind,
            auth: k.auth.clone().or(p.auth),
            mode: k.mode.or(p.mode).or(self.mode),
            verify: k.verify.clone().or(p.verify),
            slot: k.slot.clone().or(p.slot),
            algorithm: k.algorithm.clone().or(p.algorithm),
        }
    }
    fn validate_parameters(&self, p: &Provider) -> Result<()> {
        ensure!(known(&p.kind), "unknown provider kind {}", p.kind);
        let composite = matches!(
            p.kind.as_str(),
            "tpm-fido2-broker" | "tpm-piv" | "tpm-fido2-preview-sign"
        );
        if let Some(auth) = &p.auth {
            ensure!(composite, "provider {} does not accept auth", p.kind);
            let a = self
                .auth
                .get(auth)
                .with_context(|| format!("unknown auth {auth}"))?;
            let expected = match p.kind.as_str() {
                "tpm-piv" => "piv",
                "tpm-fido2-preview-sign" => "fido2-preview-sign",
                _ => "fido2",
            };
            ensure!(
                a.kind == expected,
                "provider {} requires auth kind {expected}",
                p.kind
            );
        }
        ensure!(
            p.verify.is_none() || matches!(p.kind.as_str(), "piv" | "secure-enclave"),
            "provider {} does not accept verify",
            p.kind
        );
        if let Some(v) = &p.verify {
            ensure!(
                match p.kind.as_str() {
                    "secure-enclave" => matches!(
                        v.as_str(),
                        "biometry-any" | "user-presence" | "biometry-current-set"
                    ),
                    _ => matches!(v.as_str(), "pin-touch" | "biometric-or-pin-touch"),
                },
                "unsupported verification policy {v}"
            );
        }
        ensure!(
            p.slot.is_none() || matches!(p.kind.as_str(), "piv" | "openpgp"),
            "provider {} does not accept slot",
            p.kind
        );
        if let Some(slot) = &p.slot {
            ensure!(!slot.is_empty() && slot.len() <= 32, "invalid slot");
        }
        if let Some(algorithm) = &p.algorithm {
            ensure!(
                algorithm == "p256"
                    && matches!(p.kind.as_str(), "secure-enclave" | "tpm-fido2-hmac"),
                "algorithm selection is not supported for this provider"
            );
        }
        ensure!(
            p.mode != Some(Mode::Notify) || p.kind == "secure-enclave",
            "provider {} requires mode=prompt",
            p.kind
        );
        Ok(())
    }
    pub fn resolve_for(&self, name: &str, os: &str, host: &str) -> Result<Resolved> {
        let k = self.keys.get(name).context("unknown key")?;
        let selected = k
            .kind
            .as_deref()
            .or_else(|| {
                k.provider
                    .as_ref()
                    .or(self.provider.as_ref())
                    .and_then(|s| s.select(os, host))
            })
            .unwrap_or("default");
        let selected = if selected == "default" {
            ensure!(
                os == "macos",
                "provider_unresolved: key {name} on {os} ({host}); set provider explicitly"
            );
            "secure-enclave"
        } else {
            selected
        };
        let p = self.parameters(k, selected);
        self.validate_parameters(&p)?;
        let mode = p.mode.unwrap_or(Mode::Prompt);
        ensure!(
            mode != Mode::Notify || p.verify.is_none(),
            "notify mode does not accept verify"
        );
        ensure!(
            k.bind.is_none() || !matches!(p.kind.as_str(), "secure-enclave" | "tpm-fido2-hmac"),
            "existing machine providers do not accept portable bind"
        );
        if let Some(u) = &k.uses {
            ensure!(
                !u.0.contains(&Use::Secrets) || mode == Mode::Prompt,
                "managed secrets require mode=prompt"
            );
            if matches!(p.kind.as_str(), "fido2-ssh" | "fido2-preview-sign") {
                ensure!(
                    !u.0.contains(&Use::Secrets) && !u.0.contains(&Use::OpenpgpSign),
                    "provider cannot perform requested use"
                );
            }
            if matches!(p.kind.as_str(), "fido2-hmac-secret" | "fido2-wrapped-key") {
                ensure!(u.0 == [Use::Secrets], "provider supports secrets only");
            }
            if p.kind != "openpgp" {
                ensure!(
                    !u.0.contains(&Use::OpenpgpSign),
                    "provider cannot create OpenPGP signatures"
                );
            }
            if matches!(
                p.kind.as_str(),
                "tpm-fido2-broker" | "tpm-piv" | "tpm-fido2-preview-sign"
            ) {
                ensure!(
                    !u.0.contains(&Use::Secrets)
                        || (!u.0.contains(&Use::SshAuth) && !u.0.contains(&Use::SshSign)),
                    "split TPM signing and decryption keys"
                );
            }
        } else {
            ensure!(
                matches!(p.kind.as_str(), "secure-enclave" | "tpm-fido2-hmac"),
                "new provider requires explicit use"
            );
        }
        if p.kind.contains("preview-sign") {
            ensure!(self.preview, "preview_disabled: {}", p.kind);
        }
        if matches!(
            p.kind.as_str(),
            "tpm-fido2-broker" | "tpm-piv" | "tpm-fido2-preview-sign"
        ) {
            ensure!(p.auth.is_some(), "provider {} requires auth", p.kind);
        }
        Ok(Resolved {
            kind: p.kind.clone(),
            mode,
            auth: p.auth,
            verify: p.verify,
            slot: p.slot,
            algorithm: if matches!(p.kind.as_str(), "secure-enclave" | "tpm-fido2-hmac") {
                None
            } else {
                p.algorithm
            },
        })
    }
    pub fn resolve(&self, name: &str) -> Result<Resolved> {
        self.resolve_for(name, std::env::consts::OS, &hostname()?)
    }
    pub fn effective_email(&self, name: &str) -> Option<&str> {
        self.keys
            .get(name)
            .and_then(|k| k.email.as_deref())
            .or(self.email.as_deref())
    }
    pub fn load(path: &Path) -> Result<Self> {
        let mut value = toml::Value::Table(Default::default());
        let mut sources = Vec::new();
        let mut provenance = BTreeMap::new();
        for p in [Some(path.to_owned()), local_path(path)]
            .into_iter()
            .flatten()
        {
            use std::{io::Read, os::unix::fs::OpenOptionsExt};
            let file = match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&p)
            {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e).with_context(|| format!("read {}", p.display())),
            };
            ensure!(
                file.metadata()?.is_file(),
                "config must be a regular file: {}",
                p.display()
            );
            let mut text = String::new();
            file.take(1024 * 1024 + 1).read_to_string(&mut text)?;
            ensure!(text.len() <= 1024 * 1024, "configuration exceeds 1 MiB");
            // Validate fields in each layer too, without requiring cross-layer references.
            let _: Config =
                toml::from_str(&text).with_context(|| format!("invalid config {}", p.display()))?;
            let next: toml::Value = toml::from_str(&text)?;
            merge(&mut value, next, "", &p, &mut provenance);
            sources.push(p);
        }
        let mut c = Self::parse(&toml::to_string(&value)?)
            .with_context(|| format!("load {}", path.display()))?;
        c.sources = sources;
        c.provenance = provenance;
        Ok(c)
    }
    pub fn warnings(&self) -> Vec<String> {
        self.keys.iter().filter(|(_,k)| k.github.is_some() || k.gitlab.is_some())
            .map(|(name,_)|format!("keys.{name}: github/gitlab fields are deprecated; use forge and explicit use (review role changes before migration)"))
            .collect()
    }
}
impl Resolved {
    /// Defaults apply at creation only. An omitted value never changes an existing ACL.
    pub fn for_creation(mut self) -> Self {
        if self.kind == "secure-enclave" && self.mode == Mode::Prompt && self.verify.is_none() {
            self.verify = Some("biometry-any".into());
        }
        self
    }

    pub fn matches_existing(&self, old: &Self) -> bool {
        let mut requested = self.clone();
        let mut pinned = old.clone();
        if pinned.kind == "secure-enclave" && pinned.mode == Mode::Prompt {
            pinned
                .verify
                .get_or_insert_with(|| "biometry-current-set".into());
            if requested.verify.is_none() {
                requested.verify = pinned.verify.clone();
            }
        }
        requested == pinned
    }

    pub fn ensure_available(&self) -> Result<()> {
        let c = catalog()
            .into_iter()
            .find(|c| c.kind == self.kind)
            .context("unknown provider")?;
        ensure!(
            c.status == "implemented",
            "unsupported_provider: {} is {} and not implemented",
            self.kind,
            c.status
        );
        ensure!(
            c.platform == Some(std::env::consts::OS),
            "unsupported_provider: {} requires {}",
            self.kind,
            c.platform.unwrap()
        );
        Ok(())
    }
}
pub fn local_path(path: &Path) -> Option<PathBuf> {
    let stem = path.file_stem()?.to_str()?;
    if stem.ends_with(".local") {
        return None;
    }
    Some(path.with_file_name(format!("{stem}.local.{}", path.extension()?.to_str()?)))
}
fn merge(
    dst: &mut toml::Value,
    src: toml::Value,
    prefix: &str,
    path: &Path,
    provenance: &mut BTreeMap<String, PathBuf>,
) {
    let changed_kind = dst.get("kind").is_some()
        && src.get("kind").is_some()
        && dst.get("kind") != src.get("kind");
    if prefix.ends_with(".provider")
        || prefix == "provider"
        || (changed_kind && (prefix.starts_with("providers.") || prefix.starts_with("auth.")))
    {
        *dst = src;
        provenance.retain(|k, _| k != prefix && !k.starts_with(&format!("{prefix}.")));
        provenance.insert(prefix.into(), path.into());
        return;
    }
    if let (Some(d), toml::Value::Table(s)) = (dst.as_table_mut(), &src) {
        for (key, v) in s {
            let name = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            if let Some(old) = d.get_mut(key) {
                merge(old, v.clone(), &name, path, provenance);
            } else {
                let mut old = toml::Value::Table(Default::default());
                merge(&mut old, v.clone(), &name, path, provenance);
                d.insert(key.clone(), old);
            }
        }
    } else {
        *dst = src;
        provenance.retain(|k, _| k != prefix && !k.starts_with(&format!("{prefix}.")));
        provenance.insert(prefix.into(), path.into());
    }
}
