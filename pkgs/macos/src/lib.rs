//! macOS Secure Enclave and kernel-derived socket peer identity.
#[cfg(target_os = "macos")]
mod platform;
#[cfg(target_os = "macos")]
pub use platform::*;
