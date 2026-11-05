use anyhow::{Context, Result, ensure};
use serde_json::json;

use crate::output::Output;

pub fn info(output: &Output) -> Result<()> {
    let executable = std::env::current_exe()
        .context("locate the seccy executable")?
        .canonicalize()
        .context("resolve the seccy executable")?;
    let binaries = executable.parent().context("executable has no directory")?;
    let contents = binaries
        .parent()
        .context("executable has no parent directory")?;
    ensure!(
        binaries.file_name().is_some_and(|name| name == "MacOS")
            && contents.file_name().is_some_and(|name| name == "Contents"),
        "fnox plugin is not bundled with this executable; run seccy from the packaged Seccy.app"
    );
    let plugin_dir = contents.join("Resources/fnox");
    let provider_path = plugin_dir.join("provider.lua");
    ensure!(
        provider_path.is_file(),
        "bundled fnox provider is missing at {}; reinstall the packaged app",
        provider_path.display()
    );
    output.emit(
        json!({"ok": true, "plugin_dir": plugin_dir, "provider_path": provider_path}),
        &format!(
            "Plugin directory: {}\nProvider file: {}",
            plugin_dir.display(),
            provider_path.display()
        ),
    )
}
