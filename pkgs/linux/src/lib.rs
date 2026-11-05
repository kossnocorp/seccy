//! Linux TPM/FIDO vault and desktop integration.
#![cfg(target_os = "linux")]
pub mod broker;
mod native;
mod process;
mod vault;
pub use process::caller;
pub use vault::{MAX_SECRET_BYTES, Vault, initialize};
