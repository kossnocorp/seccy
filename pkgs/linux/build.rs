fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let mut build = cc::Build::new();
    build.file("src/native.c").flag("-std=c11");
    for library in [
        "libfido2",
        "tss2-esys",
        "tss2-mu",
        "tss2-tctildr",
        "libsecret-1",
        "gcr-4",
    ] {
        let library =
            pkg_config::probe_library(library).expect("Linux development library missing");
        for path in library.include_paths {
            build.include(path);
        }
    }
    build.compile("seccy_native");
    println!("cargo:rerun-if-changed=src/native.c");
}
