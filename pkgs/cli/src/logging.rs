use anyhow::{Context, Result, ensure};
use seccy_core::storage::Paths;
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    sync::Mutex,
};
use tracing_subscriber::filter::LevelFilter;

pub fn init() -> Result<()> {
    let value = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into());
    let level: LevelFilter = value
        .parse()
        .context("LOG_LEVEL must be off, error, warn, info, debug, or trace")?;
    if level == LevelFilter::OFF {
        return Ok(());
    }
    let dir = Paths::from_env()?.state.join("logs");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    let metadata = fs::symlink_metadata(&dir)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "log directory must be owned by you and private: {}",
        dir.display()
    );
    let path = dir.join("seccy.jsonl");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.uid() == unsafe { libc::geteuid() } && metadata.nlink() == 1,
        "log must be an owned regular file with no hard links"
    );
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_max_level(level)
        .with_writer(Mutex::new(file))
        .with_thread_ids(true)
        .try_init()
        .map_err(|e| anyhow::anyhow!("initialize logging: {e}"))?;
    tracing::info!(event = "logging_started", process_id = std::process::id(), log_file = %path.display(), log_level = %value);
    Ok(())
}
