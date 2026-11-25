fn main() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../macos-ui/Sources/Copy.generated.swift");
    let source = seccy_ui::swift_source();
    if std::env::args().any(|arg| arg == "--check") {
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            source,
            "Run cargo run -p seccy_ui --example generate-swift"
        );
    } else if std::fs::read_to_string(&path).ok().as_deref() != Some(&source) {
        std::fs::write(path, source).unwrap();
    }
}
