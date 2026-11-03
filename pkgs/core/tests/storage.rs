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
    fn sign(&self, _: &Identity, _: &[u8], _: &Caller) -> Result<Vec<u8>> {
        unreachable!()
    }
}

#[test]
fn xdg_paths_and_fallbacks() {
    let paths = Paths::resolve(Some(Path::new("/home/test")), |_| None).unwrap();
    assert_eq!(paths.runtime, Path::new("/home/test/.cache/seccy/run"));
    assert_eq!(
        paths.public_key("work"),
        Path::new("/home/test/.local/share/seccy/keys/work.pub")
    );
    let paths = Paths::resolve(None, |name| {
        Some(PathBuf::from(match name {
            "XDG_RUNTIME_DIR" => "/run/user/501",
            "XDG_DATA_HOME" => "/data",
            "XDG_STATE_HOME" => "/state",
            _ => unreachable!(),
        }))
    })
    .unwrap();
    assert_eq!(paths.runtime, Path::new("/run/user/501/seccy"));
    assert_eq!(paths.keys, Path::new("/data/seccy/keys"));
    let paths = Paths::resolve(Some(Path::new("/home/test")), |_| Some("relative".into())).unwrap();
    assert_eq!(paths.runtime, Path::new("/home/test/.cache/seccy/run"));
}

#[test]
fn inventory_and_sync_update_comments_without_changing_key() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
    let mut config = Config::parse("[user]\nemail='old@example.com'\n[keys.work]\nmode='notify'\n[keys.missing]\nmode='touchid'").unwrap();
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
        .with_user(&config.user);
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

    config.user.email = Some("koss@nocorp.me".into());
    assert!(
        !key_info(&Store, &config, &paths, "work")
            .unwrap()
            .unwrap()
            .synced
    );
    let updated = key.clone().with_user(&config.user);
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
}

#[test]
fn config_missing_and_empty_are_valid_but_bad_config_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("seccy.toml");
    assert!(Config::load(&file).unwrap().keys.is_empty());
    for content in ["", "[keys]", "[user]\nemail='koss@nocorp.me'"] {
        std::fs::write(&file, content).unwrap();
        assert!(Config::load(&file).unwrap().keys.is_empty());
    }
    for content in [
        "bad toml",
        "[user]\nemail='bad comment'",
        "[user]\nemail=''",
    ] {
        std::fs::write(&file, content).unwrap();
        assert!(Config::load(&file).is_err());
    }
    assert!(Config::load(dir.path()).is_err());
}
