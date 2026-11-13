use seccy_core::{Config, state::State, storage::Paths};

#[test]
fn registry_roundtrips_sources_and_does_not_overwrite_registered_keys() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::resolve(Some(dir.path()), |_| None).unwrap();
    std::fs::create_dir_all(&paths.state).unwrap();
    let first = platform_config("email='first@example.com'\n[keys.one]\nmode='notify'").unwrap();
    let second = platform_config("[keys.one]\nmode='prompt'\nemail='ignored@example.com'\n[keys.two]\nmode='prompt'\nemail='work@example.com'\n[keys.three]\nmode='notify'").unwrap();
    let mut state = State::default();
    state
        .overlay(&first, &dir.path().join("first.toml"))
        .unwrap();
    state.save(&paths).unwrap();
    state = State::load(&paths).unwrap();
    state
        .overlay(&second, &dir.path().join("second.toml"))
        .unwrap();
    assert_eq!(state.keys["one"].config, dir.path().join("first.toml"));
    assert_eq!(state.keys["one"].mode, first.resolve("one").unwrap().mode);
    assert_eq!(
        state.keys["one"].email.as_deref(),
        Some("first@example.com")
    );
    assert_eq!(state.keys["two"].config, dir.path().join("second.toml"));
    state.save(&paths).unwrap();
    let loaded = State::load(&paths).unwrap();
    assert_eq!(loaded.keys.len(), 3);
    assert_eq!(
        loaded.keys["two"].email.as_deref(),
        Some("work@example.com")
    );
    assert_eq!(loaded.keys["three"].email, None);
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
        "[keys.test]\nmode='notify'\nconfig='/config.toml'\nemail=''",
        "[keys.test]\nmode='notify'\nconfig='/config.toml'\nemail='bad comment'",
        "invalid = [",
    ] {
        std::fs::write(paths.state.join("state.toml"), text).unwrap();
        assert!(State::load(&paths).is_err());
    }
}

fn platform_config(text: &str) -> anyhow::Result<Config> {
    if cfg!(target_os = "linux") {
        Config::parse(&format!(
            "provider='tpm-fido2-hmac'\n{}",
            text.replace("mode='notify'", "mode='prompt'")
        ))
    } else {
        Config::parse(text)
    }
}
