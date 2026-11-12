//! Secrets discovery and transactional, comment-preserving persistence. No plaintext here.
use anyhow::{Context, Result, ensure};
use seccy_core::envelope;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use toml_edit::{DocumentMut, InlineTable, Item, Value};

const MAX_FILE: u64 = 16 * 1024 * 1024;

/// Existing config directories may be readable by others; only the files need
/// private permissions. Never change permissions on an existing directory.
pub fn config_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
    {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "{} must be an owned, non-symlink directory without group/world write permissions",
        path.display()
    );
    Ok(())
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Secret {
    pub recipients: Vec<String>,
    pub value: String,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    #[serde(default)]
    recipients: BTreeMap<String, String>,
    #[serde(default)]
    secrets: BTreeMap<String, Secret>,
}
pub struct Source {
    pub path: PathBuf,
    original: Option<String>,
    pub doc: DocumentMut,
}
pub struct Config {
    pub recipients: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, Secret>,
    pub origins: BTreeMap<String, PathBuf>,
    pub sources: Vec<Source>,
    pub target: PathBuf,
}
/// Lock the destination path across atomic replacement, including its first creation.
/// Canonicalize only the parent: saving rejects symlink destinations, and the
/// destination itself may not exist yet. Hash raw path bytes without lossy UTF-8.
pub fn writer_lock(state: &Path, target: &Path) -> Result<fs::File> {
    use sha2::{Digest, Sha256};
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    };
    let absolute = std::path::absolute(target)?;
    let canonical = absolute
        .parent()
        .context("invalid secrets path")?
        .canonicalize()
        .context("resolve secrets directory")?
        .join(absolute.file_name().context("invalid secrets filename")?);
    let digest = Sha256::digest(canonical.as_os_str().as_bytes());
    crate::server::private_dir(state)?;
    let directory = state.join("secrets-locks");
    crate::server::private_dir(&directory)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join(format!("{digest:x}.lock")))?;
    let metadata = lock.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "secrets lock must be an owned private regular file"
    );
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("another Seccy process is updating this secrets file")?;
    Ok(lock)
}

fn read(path: &Path) -> Result<Option<String>> {
    use std::os::unix::fs::OpenOptionsExt;
    // Opening a malicious FIFO must not block before the regular-file check.
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("cannot read secrets configuration"),
    };
    ensure!(
        file.metadata()?.is_file(),
        "secrets configuration must be a regular file"
    );
    let mut text = String::new();
    file.take(MAX_FILE + 1).read_to_string(&mut text)?;
    ensure!(
        text.len() as u64 <= MAX_FILE,
        "secrets configuration exceeds 16 MiB"
    );
    Ok(Some(text))
}
/// Global first, then every ancestor including filesystem root, ending at cwd.
fn candidates(global: &Path, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = vec![global.to_owned()];
    for path in cwd
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|p| p.join("seccy.toml"))
    {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

pub fn detected_files(global: &Path, cwd: &Path) -> Result<Vec<PathBuf>> {
    candidates(global, cwd)
        .into_iter()
        .filter_map(|p| match p.try_exists() {
            Ok(true) => Some(Ok(p)),
            Ok(false) => None,
            Err(e) => Some(Err(e.into())),
        })
        .collect()
}

/// Public names only, for the file picker. Do not display parser diagnostics or values.
pub fn file_label(path: &Path) -> String {
    let summary = read(path)
        .ok()
        .flatten()
        .and_then(|s| toml::from_str::<Data>(&s).ok());
    let path = seccy_core::state::display_path(path);
    match summary {
        Some(data) => format!(
            "{path}  [recipients: {}; secrets: {}]",
            data.recipients
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            data.secrets.keys().cloned().collect::<Vec<_>>().join(", ")
        ),
        None => path,
    }
}

impl Config {
    pub fn load(global: &Path, cwd: &Path, file: Option<&Path>, global_only: bool) -> Result<Self> {
        ensure!(
            !(file.is_some() && global_only),
            "--secrets and --global are mutually exclusive"
        );
        let mut paths = vec![global.to_owned()];
        let target;
        if let Some(file) = file {
            target = if file.is_absolute() {
                file.to_owned()
            } else {
                cwd.join(file)
            };
            // --secrets is isolated: portable files must not depend on implicit global recipients.
            paths = vec![target.clone()];
        } else if global_only {
            target = global.to_owned();
        } else {
            for path in detected_files(global, cwd)? {
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
            target = if paths.len() > 1 {
                paths.last().unwrap().clone()
            } else {
                cwd.join("seccy.toml")
            };
            if !paths.contains(&target) {
                paths.push(target.clone());
            }
        }
        let mut result = Self {
            recipients: BTreeMap::new(),
            secrets: BTreeMap::new(),
            origins: BTreeMap::new(),
            sources: vec![],
            target,
        };
        for path in paths {
            let original = read(&path)?;
            let text = original.as_deref().unwrap_or("");
            // Never include parser diagnostics: they may echo accidentally pasted plaintext.
            let data: Data = toml::from_str(text).map_err(|_| {
                anyhow::anyhow!("invalid secrets configuration: {}", path.display())
            })?;
            let doc = text
                .parse::<DocumentMut>()
                .map_err(|_| anyhow::anyhow!("invalid secrets TOML"))?;
            for (name, recipient) in data.recipients {
                ensure!(valid_id(&name), "invalid recipient alias");
                envelope::point(&recipient)?;
                if let Some(previous) = result.recipients.get(&name) {
                    ensure!(
                        previous == &recipient,
                        "recipient alias {name} has conflicting public keys; use distinct aliases"
                    );
                }
                result.recipients.insert(name, recipient);
            }
            for (name, secret) in data.secrets {
                ensure!(envelope::valid_name(&name), "invalid secret name");
                ensure!(
                    !secret.recipients.is_empty()
                        && secret.recipients.len() <= envelope::MAX_RECIPIENTS,
                    "invalid secret recipient count"
                );
                let distinct: BTreeSet<_> = secret.recipients.iter().collect();
                ensure!(
                    distinct.len() == secret.recipients.len(),
                    "duplicate secret recipient alias"
                );
                // Validate where defined, before any descendant overrides it.
                let public = secret
                    .recipients
                    .iter()
                    .map(|r| {
                        result
                            .recipients
                            .get(r)
                            .cloned()
                            .with_context(|| format!("unknown recipient {r}"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                envelope::Envelope::parse(&secret.value, &name)?.matches(&public)?;
                result.origins.insert(name.clone(), path.clone());
                result.secrets.insert(name, secret);
            }
            result.sources.push(Source {
                path,
                original,
                doc,
            });
        }
        ensure!(
            result.secrets.len() <= 1024 && result.recipients.len() <= envelope::MAX_RECIPIENTS,
            "too many secrets or recipients"
        );
        Ok(result)
    }
    pub fn target_doc(&mut self) -> &mut DocumentMut {
        &mut self
            .sources
            .iter_mut()
            .find(|s| s.path == self.target)
            .unwrap()
            .doc
    }
    pub fn put_recipient(&mut self, name: &str, public: &str) -> Result<()> {
        ensure!(
            valid_id(name),
            "recipient alias must contain 1–64 ASCII letters, digits, underscores or hyphens"
        );
        envelope::point(public)?;
        if let Some(old) = self.recipients.get(name) {
            ensure!(
                old == public,
                "recipient alias already names another key; use a new alias"
            );
        }
        if !self.recipients.contains_key(name) {
            ensure!(
                self.recipients.len() < envelope::MAX_RECIPIENTS,
                "at most 32 recipients are supported"
            );
        }
        self.target_doc()["recipients"][name] = toml_edit::value(public);
        self.recipients.insert(name.into(), public.into());
        Ok(())
    }
    pub fn put_secret(&mut self, name: &str, secret: &Secret) {
        // Persist public dependencies too: a project file remains portable and --file works.
        for alias in &secret.recipients {
            let public = self.recipients[alias].clone();
            self.target_doc()["recipients"][alias] = toml_edit::value(public);
        }
        let recipients = secret
            .recipients
            .iter()
            .map(|s| Value::from(s.as_str()))
            .collect::<toml_edit::Array>();
        let mut entry = InlineTable::new();
        entry.insert("recipients", Value::Array(recipients));
        entry.insert("value", Value::from(secret.value.as_str()));
        self.target_doc()["secrets"][name] = Item::Value(Value::InlineTable(entry));
    }
    pub fn save(&self) -> Result<()> {
        // Detect edits while a hardware prompt was open, including inherited sources.
        for source in &self.sources {
            ensure!(
                read(&source.path)? == source.original,
                "secrets configuration changed; retry"
            );
        }
        if let Ok(meta) = fs::symlink_metadata(&self.target) {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                meta.is_file()
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.mode() & 0o022 == 0,
                "refusing to replace a symlink, foreign-owned or group/world-writable secrets file"
            );
        }
        let parent = self.target.parent().context("missing parent directory")?;
        let source = self.sources.iter().find(|s| s.path == self.target).unwrap();
        let text = source.doc.to_string();
        ensure!(
            text.len() as u64 <= MAX_FILE,
            "secrets configuration exceeds 16 MiB"
        );
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(text.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary.persist(&self.target)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}
pub fn valid_id(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn writer_lock_survives_creation_replacement_and_directory_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let project = dir.path().join("project");
        fs::create_dir(&project).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&project, &alias).unwrap();
        let target = project.join("seccy.toml");
        let lock = writer_lock(&state, &target).unwrap();
        assert!(writer_lock(&state, &alias.join("seccy.toml")).is_err());
        fs::write(&target, "").unwrap();
        assert!(writer_lock(&state, &target).is_err());
        let replacement = project.join("replacement");
        fs::write(&replacement, "# replacement").unwrap();
        fs::rename(replacement, &target).unwrap();
        assert!(writer_lock(&state, &project.join("../project/seccy.toml")).is_err());
        let other = writer_lock(&state, &project.join("other.toml")).unwrap();
        assert_eq!(fs::read_dir(&project).unwrap().count(), 1);
        assert_eq!(
            fs::read_dir(state.join("secrets-locks")).unwrap().count(),
            2
        );
        drop(lock);
        writer_lock(&state, &alias.join("seccy.toml")).unwrap();
        drop(other);
    }

    fn recipient() -> String {
        let hex = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        envelope::recipient(
            &(0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }
    fn secret(r: &str) -> Secret {
        Secret {
            recipients: vec!["mac".into()],
            value: envelope::encrypt("TOKEN", b"x", &[r.into()], |_, _| Ok("test-wrap".into()))
                .unwrap(),
        }
    }
    #[test]
    fn discovery_overlay_portability_and_atomic_conflict_detection() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global.toml");
        let project = dir.path().join("project");
        let child = project.join("nested");
        fs::create_dir_all(&child).unwrap();
        let r = recipient();
        fs::write(
            &global,
            format!("# keep global\n[recipients]\nmac = {r:?}\n"),
        )
        .unwrap();
        fs::write(project.join("seccy.toml"), "# preserve project comment\n").unwrap();
        let mut config = Config::load(&global, &child, None, false).unwrap();
        assert_eq!(config.target, project.join("seccy.toml"));
        config.put_secret("TOKEN", &secret(&r));
        config.save().unwrap();
        let text = fs::read_to_string(&config.target).unwrap();
        assert!(text.contains("# preserve project comment"));
        assert!(!text.contains("keep global"));
        let isolated = Config::load(&global, &child, Some(&config.target), false).unwrap();
        assert!(isolated.secrets.contains_key("TOKEN"));
        let mut config = Config::load(&global, &child, None, false).unwrap();
        config.put_secret("TOKEN", &secret(&r));
        fs::write(
            &global,
            format!("# externally changed\n[recipients]\nmac = {r:?}\n"),
        )
        .unwrap();
        assert!(config.save().is_err());
        assert_eq!(fs::read_to_string(&config.target).unwrap(), text);
        let local = child.join("seccy.toml");
        fs::write(&local, &text).unwrap();
        let config = Config::load(&global, &child, None, false).unwrap();
        assert_eq!(config.origins["TOKEN"], local);
        assert_eq!(config.target, local);
    }
    #[test]
    fn every_ancestor_including_root_is_a_candidate_and_closer_secrets_win() {
        let global = Path::new("/home/test/.config/seccy/secrets.toml");
        assert_eq!(
            candidates(global, Path::new("/a/b")),
            vec![
                global.to_owned(),
                PathBuf::from("/seccy.toml"),
                PathBuf::from("/a/seccy.toml"),
                PathBuf::from("/a/b/seccy.toml")
            ]
        );
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global.toml");
        let parent = dir.path().join("project");
        let cwd = parent.join("child");
        fs::create_dir_all(&cwd).unwrap();
        let public = recipient();
        for (path, unique, value) in [
            (&global, "GLOBAL_ONLY", "global"),
            (&parent.join("seccy.toml"), "PARENT_ONLY", "parent"),
            (&cwd.join("seccy.toml"), "LOCAL_ONLY", "local"),
        ] {
            let mut config = Config::load(&global, &cwd, Some(path), false).unwrap();
            config.put_recipient("mac", &public).unwrap();
            for name in ["SHARED", unique] {
                let secret = Secret {
                    recipients: vec!["mac".into()],
                    value: envelope::encrypt(
                        name,
                        value.as_bytes(),
                        std::slice::from_ref(&public),
                        |_, _| Ok("test-wrap".into()),
                    )
                    .unwrap(),
                };
                config.put_secret(name, &secret);
            }
            config.save().unwrap();
        }
        let merged = Config::load(&global, &cwd, None, false).unwrap();
        assert_eq!(merged.secrets.len(), 4);
        assert_eq!(merged.origins["SHARED"], cwd.join("seccy.toml"));
        assert_eq!(merged.origins["GLOBAL_ONLY"], global);
        assert_eq!(merged.origins["PARENT_ONLY"], parent.join("seccy.toml"));
        fs::remove_file(cwd.join("seccy.toml")).unwrap();
        let merged = Config::load(&global, &cwd, None, false).unwrap();
        assert_eq!(merged.origins["SHARED"], parent.join("seccy.toml"));
        let isolated = Config::load(&global, &cwd, None, true).unwrap();
        assert_eq!(isolated.secrets.len(), 2);
        assert_eq!(isolated.origins["SHARED"], global);
    }

    #[test]
    fn rejects_mismatched_recipients_plaintext_unknown_fields_and_symlink_writes() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global.toml");
        let target = dir.path().join("seccy.toml");
        for text in [
            "[secrets]\nTOKEN={value='plaintext',recipients=['missing']}",
            "[keys]\nfoo='bar'",
            "[recipients]\nmac='SHA256:not-a-key'",
        ] {
            fs::write(&target, text).unwrap();
            assert!(Config::load(&global, dir.path(), None, false).is_err());
        }
        fs::write(&global, "").unwrap();
        fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink(&global, &target).unwrap();
        let mut config = Config::load(&global, dir.path(), Some(&target), false).unwrap();
        config.put_recipient("mac", &recipient()).unwrap();
        assert!(config.save().is_err());
        assert_eq!(fs::read_to_string(&global).unwrap(), "");
        let fifo = dir.path().join("fifo.toml");
        use std::os::unix::ffi::OsStrExt;
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(Config::load(&global, dir.path(), Some(&fifo), false).is_err());
    }
}
