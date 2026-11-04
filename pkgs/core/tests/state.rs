use seccy_core::{Config, state::State, storage::Paths};

#[test]
fn registry_roundtrips_sources_and_does_not_overwrite_registered_keys() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
    std::fs::create_dir_all(&paths.state).unwrap();
    let first =
        Config::parse("[user]\nemail='first@example.com'\n[keys.one]\nmode='notify'").unwrap();
    let second = Config::parse("[keys.one]\nmode='touchid'\n[keys.two]\nmode='touchid'").unwrap();
    let mut state = State::default();
    state.overlay(&first, &dir.path().join("first.toml"));
    state.save(&paths).unwrap();
    state = State::load(&paths).unwrap();
    state.overlay(&second, &dir.path().join("second.toml"));
    assert_eq!(state.keys["one"].config, dir.path().join("first.toml"));
    assert_eq!(state.keys["one"].mode, seccy_core::Mode::Notify);
    assert_eq!(
        state.keys["one"].email.as_deref(),
        Some("first@example.com")
    );
    assert_eq!(state.keys["two"].config, dir.path().join("second.toml"));
    state.save(&paths).unwrap();
    assert_eq!(State::load(&paths).unwrap().keys.len(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(paths.state.join("state.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn registry_rejects_unsafe_names_relative_sources_and_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
    std::fs::create_dir_all(&paths.state).unwrap();
    for text in [
        "[keys.'../escape']\nmode='notify'\nconfig='/config.toml'",
        "[keys.test]\nmode='notify'\nconfig='relative.toml'",
        "invalid = [",
    ] {
        std::fs::write(paths.state.join("state.toml"), text).unwrap();
        assert!(State::load(&paths).is_err());
    }
}
