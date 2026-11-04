use anyhow::Result;
use output::Output;
use seccy_core::Config;
use serde_json::json;
use std::path::PathBuf;
use usage_rs::{Args, Cli, Subcommands};

#[cfg(target_os = "macos")]
mod inventory;
mod logging;
mod output;
#[cfg(target_os = "macos")]
mod secrets;
#[cfg(target_os = "macos")]
mod server;
#[cfg(target_os = "macos")]
mod service;

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
    /// Filter the JSON response with a jq expression (overrides --json)
    #[usage(long, global)]
    jq: Option<String>,
    #[usage(subcommand)]
    command: Commands,
}

#[derive(Subcommands)]
enum Commands {
    /// Idempotently create configured Secure Enclave keys
    Provision(Empty),
    /// List registered and current-config keys with their status and source
    List(Empty),
    /// Show information for a registered or current-config key
    Get(KeyArgs),
    /// Write missing or outdated public-key files
    Sync(Empty),
    /// Run the SSH agent in the foreground
    Agent(AgentArgs),
    /// Encrypt stdin with a configured public key (64 KiB maximum)
    Encrypt(KeyArgs),
    /// Decrypt ciphertext from stdin through the running agent
    Decrypt(SecretArgs),
    /// Check the running agent and selected encryption key without Touch ID
    CryptoCheck(SecretArgs),
    /// Delete a key from the registry, public files, and Keychain
    Remove(RemoveArgs),
    /// Delete all seccy keys and registry entries; preserve source configs
    Reset(ConfirmArgs),
    /// Manage the per-user login service
    Service(ServiceArgs),
}

#[derive(Args)]
struct ConfirmArgs {
    /// Skip confirmation
    #[usage(short = 'y', long)]
    yes: bool,
}

#[derive(Args)]
struct RemoveArgs {
    name: String,
    /// Skip confirmation
    #[usage(short = 'y', long)]
    yes: bool,
}

#[derive(Args)]
struct ServiceArgs {
    #[usage(subcommand)]
    command: ServiceCommand,
}

#[derive(Subcommands)]
enum ServiceCommand {
    Install(Empty),
    Uninstall(Empty),
    Status(Empty),
    Restart(Empty),
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

#[derive(Args)]
struct SecretArgs {
    /// Configured key name
    name: String,
    /// Secrets socket (defaults to the agent's secrets.sock)
    #[usage(long)]
    socket: Option<PathBuf>,
}

fn emit(output: &Output, value: serde_json::Value, text: &str) -> Result<()> {
    output.emit(value, text)
}

fn main() {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let app = match App::embedded_outcome(&argv) {
        usage_rs::embedded::Outcome::Parsed(app) => app,
        usage_rs::embedded::Outcome::Exit(exit) => {
            // The parser may exit for help or malformed commands. Preserve the
            // same output flags for those structured responses as well.
            let mut json = false;
            let mut query = None;
            let mut args = argv.iter();
            while let Some(arg) = args.next() {
                if arg == "--" {
                    break;
                }
                if arg == "--jq" {
                    query = args.next().and_then(|s| s.to_str());
                } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--jq=")) {
                    query = Some(value);
                } else if arg == "--json" {
                    json = true;
                }
            }
            let output = match Output::new(json, query) {
                Ok(output) => output,
                Err(error) => {
                    eprintln!("{error:#}");
                    std::process::exit(1);
                }
            };
            if output.structured() {
                if let Err(error) = emit(
                    &output,
                    if exit.code == 0 {
                        json!({"ok": true, "text": exit.text})
                    } else {
                        json!({"ok": false, "error": exit.text})
                    },
                    "",
                ) {
                    eprintln!("{error:#}");
                    std::process::exit(1);
                }
            } else if exit.stderr {
                eprint!("{}", exit.text);
            } else {
                print!("{}", exit.text);
            }
            std::process::exit(exit.code);
        }
    };
    let output = match Output::new(app.json, app.jq.as_deref()) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    };
    if let Err(error) = run(app, &output) {
        if error.is::<output::QueryError>() {
            tracing::error!(event = "query_failed");
            eprintln!("{error:#}");
        } else if output.structured() {
            tracing::error!(event = "command_failed", error = %format!("{error:#}"));
            if let Err(error) = emit(
                &output,
                json!({"ok": false, "error": format!("{error:#}")}),
                "",
            ) {
                eprintln!("{error:#}");
            }
        } else {
            tracing::error!(event = "command_failed", error = %format!("{error:#}"));
            eprintln!("error: {error:#}");
        }
        std::process::exit(1);
    }
}

fn run(app: App, output: &Output) -> Result<()> {
    logging::init()?;
    let command = match &app.command {
        Commands::Provision(_) => "provision",
        Commands::List(_) => "list",
        Commands::Get(_) => "get",
        Commands::Sync(_) => "sync",
        Commands::Agent(_) => "agent",
        Commands::Encrypt(_) => "encrypt",
        Commands::Decrypt(_) => "decrypt",
        Commands::CryptoCheck(_) => "crypto-check",
        Commands::Remove(_) => "remove",
        Commands::Reset(_) => "reset",
        Commands::Service(_) => "service",
    };
    tracing::info!(event = "command_started", command, config = %app.config.display());
    let config = if matches!(
        app.command,
        Commands::Agent(_)
            | Commands::Service(_)
            | Commands::Remove(_)
            | Commands::Reset(_)
            | Commands::Decrypt(_)
            | Commands::CryptoCheck(_)
    ) {
        Config::default()
    } else {
        Config::load(&app.config)?
    };
    run_platform(app, config, output)
}

#[cfg(not(target_os = "macos"))]
fn run_platform(_: App, _: Config, _: &Output) -> Result<()> {
    anyhow::bail!("Secure Enclave operations require macOS")
}

#[cfg(target_os = "macos")]
fn run_platform(app: App, config: Config, output: &Output) -> Result<()> {
    use seccy_core::storage::Paths;
    let store = seccy_macos::SecureEnclave;
    let paths = Paths::from_env()?;
    match app.command {
        command @ (Commands::Provision(_)
        | Commands::List(_)
        | Commands::Get(_)
        | Commands::Sync(_)
        | Commands::Remove(_)
        | Commands::Reset(_)) => {
            inventory::run(command, &config, &app.config, &paths, output)?;
        }
        Commands::Service(args) => service::run(args.command, &paths, output)?,
        Commands::Agent(args) => server::run(args.socket, output)?,
        Commands::Encrypt(args) => {
            use anyhow::Context;
            let _lock = inventory::read_lock(&paths)?;
            let state = inventory::view(&paths, &config, &app.config)?;
            let identity = state
                .identity(&store, &args.name)?
                .context("key is not provisioned")?;
            let input = secrets::read_stdin(seccy_macos::MAX_SECRET_BYTES)?;
            let value = store.encrypt(&identity, &input)?;
            emit(output, json!({"ok": true, "value": value}), &value)?;
        }
        Commands::Decrypt(args) => secrets::decrypt(args, output)?,
        Commands::CryptoCheck(args) => {
            let value = secrets::request(args.socket, "check", &args.name, None)?;
            emit(output, value, "Encryption key and agent are ready")?;
        }
    }
    Ok(())
}
