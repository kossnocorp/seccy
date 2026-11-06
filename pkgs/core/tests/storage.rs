use anyhow::Result;
use seccy_core::{
    Caller, Config, Identity, KeyStore, Mode,
    storage::{KeyStatus, Paths, key_info, sync_public_key},
};
use std::path::{Path, PathBuf};

struct Store;
impl KeyStore for Store {
    fn provision(&self, _: &str, _: Mode) -> Result<(Identity, bool)> {
        unreachable!()
    }
    fn identity(&self, name: &str, mode: Mode) -> Result<Option<Identity>> {
        if name == "missing" {
            return Ok(None);
        }
        let key = p256::ecdsa::SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        Identity::new(
            name,
            mode,
            key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .map(Some)
    }
    fn sign(
        &self,
        _: &Identity,
        _: &[u8],
        _: &Caller,
        _: &seccy_core::payload::Payload,
    ) -> Result<Vec<u8>> {
        unreachable!()
    }
}

#[test]
fn xdg_paths_and_fallbacks() {
    let paths = Paths::resolve(Some(Path::new("/home/test")), |_| None).unwrap();
    assert_eq!(
        paths.config,
        Path::new("/home/test/.config/seccy/config.toml")
    );
    assert_eq!(paths.runtime, Path::new("/home/test/.local/state/seccy"));
    assert_eq!(
        paths.public_key("work"),
        Path::new("/home/test/.local/state/seccy/keys/work.pub")
    );
    let paths = Paths::resolve(None, |name| {
        Some(PathBuf::from(match name {
            "XDG_RUNTIME_DIR" => "/run/user/501",
            "XDG_DATA_HOME" => "/data",
            "XDG_CONFIG_HOME" => "/config",
            "XDG_STATE_HOME" => "/state",
            _ => unreachable!(),
        }))
    })
    .unwrap();
    assert_eq!(paths.runtime, Path::new("/run/user/501/seccy"));
    assert_eq!(paths.keys, Path::new("/state/seccy/keys"));
    assert_eq!(paths.config, Path::new("/config/seccy/config.toml"));
    let paths = Paths::resolve(Some(Path::new("/home/test")), |_| Some("relative".into())).unwrap();
    assert_eq!(paths.runtime, Path::new("/home/test/.local/state/seccy"));
    assert_eq!(
        paths.config,
        Path::new("/home/test/.config/seccy/config.toml")
    );
    let paths = Paths::resolve(Some(Path::new("/home/test")), |_| Some("".into())).unwrap();
    assert_eq!(
        paths.config,
        Path::new("/home/test/.config/seccy/config.toml")
    );
}

#[test]
fn inventory_and_sync_update_comments_without_changing_key() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
    let mut config = Config::parse(
        "email='old@example.com'\n[keys.work]\nmode='notify'\n[keys.missing]\nmode='prompt'",
    )
    .unwrap();
    let missing = key_info(&Store, &config, &paths, "missing")
        .unwrap()
        .unwrap();
    assert!(matches!(missing.status, KeyStatus::NotProvisioned));
    assert!(missing.public_key.is_none());
    assert!(!missing.synced);
    assert!(
        key_info(&Store, &config, &paths, "unknown")
            .unwrap()
            .is_none()
    );
    let key = Store
        .identity("work", Mode::Notify)
        .unwrap()
        .unwrap()
        .with_email(config.effective_email("work"));
    assert!(sync_public_key(&key, &paths).unwrap());
    let modified = std::fs::metadata(paths.public_key("work"))
        .unwrap()
        .modified()
        .unwrap();
    assert!(!sync_public_key(&key, &paths).unwrap());
    assert_eq!(
        modified,
        std::fs::metadata(paths.public_key("work"))
            .unwrap()
            .modified()
            .unwrap()
    );
    assert!(
        key_info(&Store, &config, &paths, "work")
            .unwrap()
            .unwrap()
            .synced
    );

    config.email = Some("koss@nocorp.me".into());
    assert!(
        !key_info(&Store, &config, &paths, "work")
            .unwrap()
            .unwrap()
            .synced
    );
    let updated = key.clone().with_email(config.effective_email("work"));
    assert_eq!(key.blob, updated.blob);
    assert_eq!(key.fingerprint, updated.fingerprint);
    assert!(sync_public_key(&updated, &paths).unwrap());
    assert_eq!(
        std::fs::read_to_string(paths.public_key("work")).unwrap(),
        format!("{}\n", updated.public_key)
    );
    assert!(updated.public_key.ends_with(" koss@nocorp.me"));
    assert!(
        key_info(&Store, &config, &paths, "work")
            .unwrap()
            .unwrap()
            .synced
    );

    for (default, override_email, expected) in [
        (
            Some("default@example.com"),
            Some("work@example.com"),
            "work@example.com",
        ),
        (None, Some("work@example.com"), "work@example.com"),
        (Some("default@example.com"), None, "default@example.com"),
        (None, None, "work"),
    ] {
        config.email = default.map(str::to_owned);
        config.keys.get_mut("work").unwrap().email = override_email.map(str::to_owned);
        let identity = key.clone().with_email(config.effective_email("work"));
        sync_public_key(&identity, &paths).unwrap();
        let info = key_info(&Store, &config, &paths, "work").unwrap().unwrap();
        assert!(info.synced);
        assert_eq!(info.fingerprint.as_deref(), Some(key.fingerprint.as_str()));
        assert!(info.public_key.unwrap().ends_with(&format!(" {expected}")));
    }
}

#[test]
fn config_missing_and_empty_are_valid_but_bad_config_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.toml");
    assert!(Config::load(&file).unwrap().keys.is_empty());
    for content in ["", "[keys]", "email='koss@nocorp.me'"] {
        std::fs::write(&file, content).unwrap();
        assert!(Config::load(&file).unwrap().keys.is_empty());
    }
    for content in [
        "bad toml",
        "email='bad comment'",
        "email=''",
        "[user]\nemail='valid@example.com'",
    ] {
        std::fs::write(&file, content).unwrap();
        let error = format!("{:#}", Config::load(&file).unwrap_err());
        assert!(error.contains(file.to_str().unwrap()), "{error}");
    }
    assert!(Config::load(dir.path()).is_err());
}
