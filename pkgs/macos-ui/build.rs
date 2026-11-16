use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=Sources");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        arch => panic!("unsupported macOS architecture: {arch}"),
    };
    let sdk = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .expect("Xcode is required");
    assert!(sdk.status.success(), "cannot locate the macOS SDK");
    let sdk = String::from_utf8(sdk.stdout).unwrap();
    let status = Command::new("xcrun")
        .args([
            "swiftc",
            "-emit-library",
            "-static",
            "-parse-as-library",
            "-O",
            "-module-name",
            "SeccyUI",
            "-swift-version",
            "5",
            "-sdk",
            sdk.trim(),
            "-target",
            &format!("{arch}-apple-macosx12.0"),
            "Sources/Notifications.swift",
            "Sources/UITrace.swift",
            "Sources/AuthorizationView.swift",
            "Sources/Bridge.swift",
            "-o",
        ])
        .arg(out.join("libSeccyUI.a"))
        .status()
        .expect("run Swift compiler");
    assert!(status.success(), "SwiftUI compilation failed");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!(
        "cargo:rustc-link-search=native={}/usr/lib/swift",
        sdk.trim()
    );
    let compiler = Command::new("xcrun")
        .args(["--find", "swiftc"])
        .output()
        .expect("locate Swift compiler");
    assert!(compiler.status.success());
    let compiler = PathBuf::from(String::from_utf8(compiler.stdout).unwrap().trim());
    let toolchain = compiler.parent().unwrap().parent().unwrap();
    println!(
        "cargo:rustc-link-search=native={}/lib/swift/macosx",
        toolchain.display()
    );
    println!("cargo:rustc-link-lib=static=SeccyUI");
    for framework in [
        "CoreServices",
        "UserNotifications",
        "AppKit",
        "SwiftUI",
        "LocalAuthentication",
        "LocalAuthenticationEmbeddedUI",
    ] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}
