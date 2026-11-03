use anyhow::Result;
use seccy_core::Config;
use serde_json::{Value, json};
use std::path::PathBuf;
use usage_rs::{Args, Cli, Subcommands};

#[cfg(target_os = "macos")]
mod server;

/// Secure Enclave SSH authentication and Git signing
#[derive(Cli)]
#[usage(bin = "seccy", version)]
struct App {
    /// Configuration file
    #[usage(long, global, default = "seccy.toml")]
    config: PathBuf,
    /// Emit JSON (agent emits one object per line)
    #[usage(long, global)]
    json: bool,
    #[usage(subcommand)]
    command: Commands,
}

#[derive(Subcommands)]
enum Commands {
    /// Idempotently create configured Secure Enclave keys
    Provision(Empty),
    /// List configured keys and their provisioning and public-file status
    List(Empty),
    /// Show information for a configured key
    Get(KeyArgs),
    /// Write missing or outdated public-key files
    Sync(Empty),
    /// Run the SSH agent in the foreground
    Agent(AgentArgs),
}

#[derive(Args)]
struct Empty {}

#[derive(Args)]
struct KeyArgs {
    /// Configured key name
    name: String,
}

#[derive(Args)]
struct AgentArgs {
    /// Socket path; parent directory must be private and owned by you
    #[usage(long)]
    socket: Option<PathBuf>,
}

fn emit(json_mode: bool, value: Value, text: &str) {
    if json_mode {
        println!("{value}");
    } else if !text.is_empty() {
        println!("{text}");
    }
}

fn main() {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let json_mode = argv
        .iter()
        .take_while(|a| *a != "--")
        .any(|a| a == "--json");
    let app = match App::embedded_outcome(&argv) {
        usage_rs::embedded::Outcome::Parsed(app) => app,
        usage_rs::embedded::Outcome::Exit(exit) => {
            if json_mode {
                emit(
                    true,
                    if exit.code == 0 {
                        json!({"ok": true, "text": exit.text})
                    } else {
                        json!({"ok": false, "error": exit.text})
                    },
                    "",
                );
            } else if exit.stderr {
                eprint!("{}", exit.text);
            } else {
                print!("{}", exit.text);
            }
            std::process::exit(exit.code);
        }
    };
    if let Err(error) = run(app) {
        if json_mode {
            emit(
                true,
                json!({"ok": false, "error": format!("{error:#}")}),
                "",
            );
        } else {
            eprintln!("error: {error:#}");
        }
        std::process::exit(1);
    }
}

fn run(app: App) -> Result<()> {
    let config = Config::load(&app.config)?;
    run_platform(app, config)
}

#[cfg(not(target_os = "macos"))]
fn run_platform(_: App, _: Config) -> Result<()> {
    anyhow::bail!("Secure Enclave operations require macOS")
}

#[cfg(target_os = "macos")]
fn run_platform(app: App, config: Config) -> Result<()> {
    use seccy_core::KeyStore;
    use seccy_core::storage::{KeyInfo, Paths, key_info, sync_public_key};
    let store = seccy_macos::SecureEnclave;
    let paths = Paths::from_env()?;
    match app.command {
        Commands::Provision(_) => {
            server::private_dir(&paths.state)?;
            let _lock = server::lock(&paths.state.join("provision.lock"))?;
            let mut keys = Vec::new();
            for (name, key) in &config.keys {
                let (identity, created) = store.provision(name, key.mode)?;
                let identity = identity.with_user(&config.user);
                let updated = sync_public_key(&identity, &paths)?;
                let info = KeyInfo::new(name, key.mode, Some(&identity), &paths)?;
                keys.push(json!({"key": info, "created": created, "updated": updated}));
            }
            emit(
                app.json,
                json!({"ok": true, "keys": keys}),
                if keys.is_empty() {
                    ""
                } else {
                    "Configured keys are provisioned and public files synced"
                },
            );
        }
        Commands::List(_) => {
            let keys = config
                .keys
                .keys()
                .map(|name| key_info(&store, &config, &paths, name))
                .collect::<Result<Vec<_>>>()?;
            let keys: Vec<_> = keys.into_iter().flatten().collect();
            let text = keys
                .iter()
                .map(KeyInfo::text)
                .collect::<Vec<_>>()
                .join("\n");
            emit(app.json, json!({"ok": true, "keys": keys}), &text);
        }
        Commands::Get(args) => {
            let key = key_info(&store, &config, &paths, &args.name)?;
            let text = key.as_ref().map(KeyInfo::text).unwrap_or_default();
            emit(app.json, json!({"ok": true, "key": key}), &text);
        }
        Commands::Sync(_) => {
            server::private_dir(&paths.state)?;
            let _lock = server::lock(&paths.state.join("provision.lock"))?;
            let mut keys = Vec::new();
            let mut text = Vec::new();
            for (name, key) in &config.keys {
                let identity = store
                    .identity(name, key.mode)?
                    .map(|i| i.with_user(&config.user));
                let updated = match &identity {
                    Some(identity) => sync_public_key(identity, &paths)?,
                    None => false,
                };
                let info = KeyInfo::new(name, key.mode, identity.as_ref(), &paths)?;
                text.push(info.text());
                keys.push(json!({"key": info, "updated": updated}));
            }
            emit(
                app.json,
                json!({"ok": true, "keys": keys}),
                &text.join("\n"),
            );
        }
        Commands::Agent(args) => server::run(config, args.socket, app.json)?,
    }
    Ok(())
}
