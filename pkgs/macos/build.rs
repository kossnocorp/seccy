fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rerun-if-changed=src/process_fallback.c");
        cc::Build::new()
            .file("src/process_fallback.c")
            .compile("process_fallback");
    }
}
