use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use crate::output::Output;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize, Serialize)]
struct Metadata {
    version: String,
}

const PROVIDER: &[u8] = include_bytes!("../../fnox/provider.lua");

fn installed_dir() -> Result<PathBuf> {
    let data = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    let data = match data {
        Some(path) => path,
        None => env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .context("HOME must be absolute when XDG_DATA_HOME is unset")?
            .join(".local/share"),
    };
    Ok(data.join("seccy/fnox"))
}

/// Install or update from the source embedded at compile time.
pub fn init(output: &Output) -> Result<()> {
    let plugin_dir = installed_dir()?;
    fs::create_dir_all(&plugin_dir).with_context(|| format!("create {}", plugin_dir.display()))?;
    write_file(&plugin_dir.join("provider.lua"), PROVIDER)?;
    let metadata = serde_json::to_vec_pretty(&Metadata {
        version: VERSION.into(),
    })?;
    write_file(&plugin_dir.join("metadata.json"), &metadata)?;
    emit_location(output, plugin_dir, Some(VERSION.into()))
}

fn write_file(path: &Path, content: &[u8]) -> Result<()> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().context("file has no directory")?)?;
    temporary.write_all(content)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .with_context(|| format!("install {}", path.display()))?;
    Ok(())
}

fn installed_version(plugin_dir: &Path) -> Result<Option<String>> {
    let path = plugin_dir.join("metadata.json");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let metadata: Metadata = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "invalid plugin metadata at {}; run seccy fnox init to repair",
            path.display()
        )
    })?;
    ensure!(
        !metadata.version.trim().is_empty(),
        "plugin version is empty at {}; run seccy fnox init to repair",
        path.display()
    );
    Ok(Some(metadata.version))
}

pub fn info(output: &Output) -> Result<()> {
    let plugin_dir = installed_dir()?;
    if plugin_dir.join("provider.lua").is_file() {
        let version = installed_version(&plugin_dir)?;
        return emit_location(output, plugin_dir, version);
    }
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
        "fnox plugin is not installed or bundled with this executable; run seccy fnox init or use the packaged Seccy.app"
    );
    let plugin_dir = contents.join("Resources/fnox");
    let provider_path = plugin_dir.join("provider.lua");
    ensure!(
        provider_path.is_file(),
        "bundled fnox provider is missing at {}; run seccy fnox init or reinstall the packaged app",
        provider_path.display()
    );
    emit_location(output, plugin_dir, Some(VERSION.into()))
}

fn emit_location(output: &Output, plugin_dir: PathBuf, version: Option<String>) -> Result<()> {
    let provider_path = plugin_dir.join("provider.lua");
    output.emit(
        json!({"ok": true, "plugin_dir": plugin_dir, "provider_path": provider_path, "version": version, "binary_version": VERSION}),
        &format!(
            "Plugin directory: {}\nProvider file: {}\nPlugin version: {}\nBinary version: {}",
            plugin_dir.display(),
            provider_path.display(),
            version.as_deref().unwrap_or("unknown"),
            VERSION
        ),
    )
}
