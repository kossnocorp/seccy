use seccy_core::Config;

#[test]
fn emails_resolve_override_then_default_then_no_email() {
    let mut config = Config::parse(
        "email='personal@example.com'\n[keys.personal]\nmode='notify'\n[keys.work]\nmode='prompt'\nemail='work@example.com'",
    )
    .unwrap();
    assert_eq!(
        config.effective_email("personal"),
        Some("personal@example.com")
    );
    assert_eq!(config.effective_email("work"), Some("work@example.com"));
    config.email = None;
    assert_eq!(config.effective_email("personal"), None);
    assert_eq!(config.effective_email("work"), Some("work@example.com"));
    config.keys.get_mut("work").unwrap().email = None;
    assert_eq!(config.effective_email("work"), None);
}

#[test]
fn invalid_emails_identify_the_field_at_both_levels() {
    for email in [
        "",
        "bad comment",
        "tab\there",
        "line\nbreak",
        "control\0",
        "delete\u{7f}",
        "unicode\u{a0}space",
    ] {
        let value = toml::Value::String(email.into()).to_string();
        for (text, field) in [
            (format!("email={value}"), "email"),
            (
                format!("[keys.work]\nmode='prompt'\nemail={value}"),
                "keys.work.email",
            ),
        ] {
            let error = format!("{:#}", Config::parse(&text).unwrap_err());
            assert!(
                error.contains(&format!("{field} must be nonempty")),
                "{error}"
            );
        }
    }
    // An override must not hide an invalid default.
    assert!(
        Config::parse("email=''\n[keys.work]\nmode='prompt'\nemail='valid@example.com'").is_err()
    );
}

#[test]
fn obsolete_user_table_is_rejected_even_when_empty() {
    for text in ["[user]", "[user]\nemail='valid@example.com'"] {
        let error = format!("{:#}", Config::parse(text).unwrap_err());
        assert!(error.contains("unknown field `user`"), "{error}");
    }
}

#[test]
fn experimental_macos_ui_is_explicitly_opt_in() {
    assert!(!Config::default().experimental.macos_ui);
    for text in ["", "[experimental]", "[experimental]\nmacos_ui=false"] {
        assert!(!Config::parse(text).unwrap().experimental.macos_ui);
    }
    assert!(
        Config::parse("[experimental]\nmacos_ui=true")
            .unwrap()
            .experimental
            .macos_ui
    );
    assert!(Config::parse("[experimental]\nmacos_ui='true'").is_err());
    assert!(Config::parse("[experimental]\nunknown=true").is_err());
    assert!(Config::parse("[experimental]\nui=true").is_err());
}
