use seccy_core::{
    Config, Mode,
    config::{Forge, Use},
};

#[test]
fn defaults_selectors_and_inline_precedence() {
    let c = Config::parse("[keys.auth]\nuse='ssh-auth'").unwrap();
    assert_eq!(
        c.resolve_for("auth", "macos", "host").unwrap().kind,
        "secure-enclave"
    );
    assert!(
        c.resolve_for("auth", "linux", "host")
            .unwrap_err()
            .to_string()
            .contains("provider_unresolved")
    );
    let c = Config::parse(
        r#"
provider = { host = { pc = "pc" } }
mode = "prompt"
[providers.pc]
kind = "tpm-fido2-hmac"
[keys.auth]
use = "ssh-auth"
[keys.signing]
kind = "secure-enclave"
mode = "notify"
use = "ssh-sign"
"#,
    )
    .unwrap();
    assert_eq!(
        c.resolve_for("auth", "linux", "pc").unwrap().kind,
        "tpm-fido2-hmac"
    );
    assert!(c.resolve_for("auth", "linux", "other").is_err());
    assert_eq!(
        c.resolve_for("auth", "macos", "other").unwrap().kind,
        "secure-enclave"
    );
    assert_eq!(
        c.resolve_for("signing", "linux", "pc").unwrap().mode,
        Mode::Notify
    );
    let c = Config::parse(
        r#"
provider='notify'
[providers.notify]
kind='secure-enclave'
mode='notify'
[keys.auth]
use='ssh-auth'
[keys.override]
provider={os={linux='tpm-fido2-hmac'}}
use='ssh-auth'
"#,
    )
    .unwrap();
    assert_eq!(
        c.resolve_for("auth", "macos", "x").unwrap().mode,
        Mode::Notify
    );
    assert_eq!(
        c.resolve_for("override", "macos", "x").unwrap().mode,
        Mode::Prompt
    );
}

#[test]
fn inline_fields_override_named_provider_without_changing_kind() {
    let c = Config::parse(
        r#"
provider='card'
[providers.card]
kind='piv'
verify='pin-touch'
slot='9a'
[keys.recovery]
use=['secrets']
slot='9d'
verify='biometric-or-pin-touch'
"#,
    )
    .unwrap();
    let r = c.resolve_for("recovery", "macos", "x").unwrap();
    assert_eq!(r.slot.as_deref(), Some("9d"));
    assert_eq!(r.verify.as_deref(), Some("biometric-or-pin-touch"));
    assert!(
        r.ensure_available()
            .unwrap_err()
            .to_string()
            .contains("not implemented")
    );
}

#[test]
fn normalization_forge_and_deprecated_roles() {
    let a = Config::parse("[keys.auth]\nuse='ssh-auth'\nforge='github'").unwrap();
    let b = Config::parse("[keys.auth]\nuse=['ssh-auth']\nforge=['github']").unwrap();
    assert_eq!(a.keys["auth"].uses, b.keys["auth"].uses);
    assert_eq!(a.keys["auth"].forge, b.keys["auth"].forge);
    assert_eq!(a.keys["auth"].uses.as_ref().unwrap().0, [Use::SshAuth]);
    assert_eq!(a.keys["auth"].forge.as_ref().unwrap().0, [Forge::Github]);
    let c = Config::parse("[keys.auth]\nuse=['ssh-auth','ssh-sign']\nforge=['github','gitlab']")
        .unwrap();
    assert_eq!(c.keys["auth"].github_roles().len(), 2);
    assert!(
        Config::parse("[keys.auth]\nuse=['ssh-auth','ssh-sign']\ngitlab=['auth','signing']")
            .is_ok()
    );
}

#[test]
fn rejects_ambiguous_unsafe_or_unknown_settings() {
    for text in [
        "provider={os={},host={}}",
        "provider={os={windows='secure-enclave'}}",
        "provider='missing'",
        "[providers.default]\nkind='secure-enclave'",
        "[keys.a]\nkind='secure-enclave'\nprovider='default'",
        "[keys.a]\nmode='signing'",
        "[keys.a]\nuse=[]",
        "[keys.a]\nuse=['secrets','secrets']",
        "[keys.a]\nuse='magic'",
        "[keys.a]\nuses=['secrets']",
        "[keys.a]\nforge='github'",
        "[keys.a]\nuse='secrets'\nforge='gitlab'",
        "[keys.a]\nuse='ssh-auth'\nforge='github'\ngithub='auth'",
        "[keys.a]\nuse='ssh-auth'\ngitlab='signing'",
        "[keys.a]\nkind='secure-enclave'\nauth='x'",
        "[keys.a]\nkind='tpm-fido2-hmac'\nmode='notify'",
        "[keys.a]\nkind='secure-enclave'\nverify='pin-touch'",
        "[providers.x]\nkind='unknown'",
        "[auth.x]\nkind='piv'\nverify='pin-only'",
    ] {
        assert!(Config::parse(text).is_err(), "{text}");
    }
    for text in [
        "[keys.a]\nmode='notify'\nuse='secrets'",
        "[keys.a]\nkind='fido2-ssh'\nuse='secrets'",
        "[keys.a]\nkind='fido2-preview-sign'\nuse='ssh-sign'",
        "[keys.a]\nkind='tpm-fido2-broker'\nuse='ssh-auth'",
    ] {
        let c = Config::parse(text).unwrap();
        assert!(c.resolve_for("a", "macos", "x").is_err(), "{text}");
    }
}

#[test]
fn config_overlays_replace_selectors_and_preserve_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("config.toml");
    let local = dir.path().join("config.local.toml");
    std::fs::write(&base,"provider={os={macos='secure-enclave',linux='tpm-fido2-hmac'}}\n[keys.a]\nuse='ssh-auth'\nmode='prompt'").unwrap();
    std::fs::write(
        &local,
        "provider={host={only='secure-enclave'}}\n[keys.a]\nmode='notify'",
    )
    .unwrap();
    let c = Config::load(&base).unwrap();
    assert_eq!(
        c.resolve_for("a", "macos", "other").unwrap().mode,
        Mode::Notify
    );
    assert!(c.resolve_for("a", "linux", "other").is_err());
    assert_eq!(c.provenance["keys.a.mode"], local);
    assert_eq!(c.provenance["provider"], local);
    std::fs::remove_file(&base).unwrap();
    assert_eq!(Config::load(&base).unwrap().sources, [local]);
}

#[test]
fn local_kind_changes_do_not_retain_parameters_from_other_providers() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("config.toml");
    let local = dir.path().join("config.local.toml");
    std::fs::write(&base,"provider='chosen'\n[providers.chosen]\nkind='piv'\nverify='pin-touch'\n[keys.a]\nuse='ssh-auth'").unwrap();
    std::fs::write(&local, "[providers.chosen]\nkind='secure-enclave'").unwrap();
    let c = Config::load(&base).unwrap();
    assert_eq!(c.resolve_for("a", "macos", "h").unwrap().verify, None);
    std::fs::write(
        &local,
        "[keys.a]\nkind='secure-enclave'\nprovider='default'",
    )
    .unwrap();
    assert!(Config::load(&base).is_err());
}
