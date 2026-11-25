//! SwiftUI presentation; Rust retains ownership of requests and key operations.
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Request {
    pub presentation: seccy_ui::prompt::Prompt,
    pub diagnostics: String,
    pub details: String,
    pub content: seccy_ui::Content,
    #[serde(rename = "pidLabel")]
    pub pid_label: String,
    pub key: String,
    pub fingerprint: String,
    #[serde(rename = "keyInfo")]
    pub key_info: Vec<KeyInfo>,
    pub executable: String,
    pub pid: i32,
    pub processes: Vec<Process>,
    #[serde(rename = "ancestryInterruption")]
    pub ancestry_interruption: Option<String>,
    pub header: seccy_ui::Header,
    #[serde(rename = "appPid")]
    pub app_pid: i32,
    #[serde(rename = "workingDirectory")]
    pub working_directory: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub name: String,
    pub fingerprint: String,
    pub algorithm: Option<String>,
    pub public_key_path: Option<std::path::PathBuf>,
}

/// Presentation-only snapshots, requester first, then nearest parent first.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    pub limited: bool,
    pub diagnostics: String,
    pub pid: i32,
    pub pid_label: String,
    pub name: String,
    pub executable: Option<String>,
    pub start_seconds: u64,
    pub start_microseconds: u64,
    pub bundle_paths: Vec<String>,
}

pub fn pid_label(pid: i32) -> String {
    seccy_ui::text("ui-pid", &[("pid", &pid.to_string())])
}

#[cfg(target_os = "macos")]
mod native {
    use super::Request;
    use anyhow::{Context, Result};
    use objc2::rc::Retained;
    use objc2_foundation::NSString;
    use objc2_local_authentication::LAContext;
    use std::{
        ffi::{CString, c_char, c_void},
        sync::{
            Mutex, MutexGuard,
            atomic::{AtomicBool, Ordering},
        },
    };

    static AUTHORIZATION: Mutex<()> = Mutex::new(());
    static CUSTOM_UI: AtomicBool = AtomicBool::new(false);
    unsafe extern "C" {
        fn seccy_notifications_configure();
        fn seccy_notify(title: *const c_char, body: *const c_char) -> i32;
        fn seccy_ui_run(entry: extern "C" fn());
        fn seccy_ui_authenticate(request: *const c_char) -> *mut c_void;
        fn seccy_ui_capture(
            request: *const c_char,
            directory: *const c_char,
            mode: *const c_char,
        ) -> i32;
    }

    /// Install the native notification delegate without requesting permission.
    /// Independent of the experimental authentication UI setting.
    pub fn configure_notifications() {
        unsafe { seccy_notifications_configure() };
    }

    pub fn notify(title: &str, body: &str) -> Result<()> {
        let title = CString::new(title)?;
        let body = CString::new(body)?;
        // Swift copies both strings before returning; no pointers escape this call.
        let result = unsafe { seccy_notify(title.as_ptr(), body.as_ptr()) };
        match result {
            0 => Ok(()),
            1 => anyhow::bail!(
                "native notifications require Seccy.app; run the signed bundled executable"
            ),
            2 => anyhow::bail!(
                "notifications disabled; enable Seccy in System Settings > Notifications"
            ),
            4 => anyhow::bail!("notification permission or submission timed out"),
            _ => anyhow::bail!("macOS could not authorize or submit the notification"),
        }
    }

    /// Run on the process main thread. The entry point runs on a worker and must exit.
    pub fn run(entry: extern "C" fn()) {
        CUSTOM_UI.store(true, Ordering::Release);
        run_capture(entry);
    }

    /// Keep AppKit available for icon snapshots without changing system prompts.
    pub fn run_capture(entry: extern "C" fn()) {
        unsafe { seccy_ui_run(entry) };
    }

    /// Snapshot presentation and resolved icons before the key operation.
    pub fn capture(request: &Request, directory: &str, mode: &str) -> Result<()> {
        let request = CString::new(serde_json::to_string(request)?)?;
        let directory = CString::new(directory)?;
        let mode = CString::new(mode)?;
        anyhow::ensure!(
            unsafe { seccy_ui_capture(request.as_ptr(), directory.as_ptr(), mode.as_ptr()) } == 0,
            "could not save request capture"
        );
        Ok(())
    }

    /// A fresh context bound to one operation or explicit batch; never cached.
    pub struct Authorization(
        Retained<LAContext>,
        #[allow(dead_code)] Option<MutexGuard<'static, ()>>,
    );
    impl Authorization {
        pub fn context(&self) -> &LAContext {
            &self.0
        }
    }
    impl Drop for Authorization {
        fn drop(&mut self) {
            // Invalidate on success AND every error path, including failed key lookup.
            unsafe { self.0.invalidate() };
        }
    }

    pub fn authenticate(request: &Request) -> Result<Authorization> {
        if !CUSTOM_UI.load(Ordering::Acquire) {
            // Preserve the original system prompt and its exact plain-text reason.
            // Security.framework starts authentication during the key operation.
            let context = unsafe { LAContext::new() };
            unsafe {
                context.setLocalizedReason(&NSString::from_str(&request.details));
                context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
            }
            return Ok(Authorization(context, None));
        }
        let guard = AUTHORIZATION
            .lock()
            .map_err(|_| anyhow::anyhow!("authorization lock poisoned"))?;
        let json = CString::new(serde_json::to_string(request)?)?;
        // Swift transfers one retained LAContext after its modal UI has finished.
        // No Swift callback accesses it after transfer. Rust owns it until drop.
        let context =
            unsafe { Retained::from_raw(seccy_ui_authenticate(json.as_ptr()).cast::<LAContext>()) }
                .context("authorization cancelled, unavailable, or timed out")?;
        Ok(Authorization(context, Some(guard)))
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn unbundled_notification_reports_error_without_system_prompt() {
            let error = notify("seccy: test", "No key operation").unwrap_err();
            assert!(error.to_string().contains("signed bundled executable"));
        }

        #[test]
        fn default_context_preserves_original_system_prompt_reason() {
            let details = "Approve the git commit?\n\nThe process chain Terminal → git commit wants to use the work key to sign a Git commit.";
            let authorization = authenticate(&Request {
                presentation: seccy_ui::prompt::Prompt::new(
                    &seccy_ui::Operation::GitCommit,
                    vec![],
                    None,
                    &["work".into()],
                ),
                diagnostics: "{}".into(),
                details: details.into(),
                content: seccy_ui::Content::default(),
                pid_label: crate::pid_label(123),
                key: "work".into(),
                fingerprint: "sample".into(),
                key_info: vec![],
                executable: "/usr/bin/git".into(),
                pid: 123,
                processes: vec![],
                ancestry_interruption: None,
                header: seccy_ui::Activity {
                    operation: seccy_ui::Operation::GitCommit,
                    key: "work".into(),
                    chain: "git".into(),
                    directory: None,
                    warnings: vec![],
                }
                .header("git"),
                app_pid: 123,
                working_directory: None,
            })
            .unwrap();
            unsafe {
                assert_eq!(
                    authorization.context().localizedReason().to_string(),
                    details
                );
                assert_eq!(
                    authorization
                        .context()
                        .touchIDAuthenticationAllowableReuseDuration(),
                    0.0
                );
                assert!(authorization.context().localizedFallbackTitle().is_none());
            }
        }
    }
}
#[cfg(target_os = "macos")]
pub use native::*;
