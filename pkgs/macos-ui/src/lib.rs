//! SwiftUI presentation; Rust retains ownership of requests and key operations.
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Request {
    pub details: String,
    pub key: String,
    pub fingerprint: String,
    pub executable: String,
    pub pid: i32,
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
    static RUNNING: AtomicBool = AtomicBool::new(false);
    unsafe extern "C" {
        fn seccy_notifications_configure();
        fn seccy_notify(title: *const c_char, body: *const c_char) -> i32;
        fn seccy_ui_run(entry: extern "C" fn());
        fn seccy_ui_authenticate(request: *const c_char) -> *mut c_void;
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
        RUNNING.store(true, Ordering::Release);
        unsafe { seccy_ui_run(entry) };
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
        if !RUNNING.load(Ordering::Acquire) {
            // Preserve the original system prompt and its exact plain-text reason.
            // Security.framework starts authentication during the key operation.
            let context = unsafe { LAContext::new() };
            unsafe {
                context.setLocalizedReason(&NSString::from_str(&request.details));
                context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
                context.setLocalizedFallbackTitle(Some(&NSString::from_str("")));
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
                details: details.into(),
                key: "work".into(),
                fingerprint: "sample".into(),
                executable: "/usr/bin/git".into(),
                pid: 123,
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
                assert_eq!(
                    authorization
                        .context()
                        .localizedFallbackTitle()
                        .unwrap()
                        .to_string(),
                    ""
                );
            }
        }
    }
}
#[cfg(target_os = "macos")]
pub use native::*;
