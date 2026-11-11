use anyhow::Result;
use output::Output;
use seccy_core::Config;
use serde_json::json;
use std::path::PathBuf;
use usage_rs::{Args, Cli, Subcommands};

mod activate;
mod fnox;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod gh;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod inventory;
mod logging;
mod output;
mod secret_args;
#[cfg(target_os = "macos")]
mod secret_config;
#[cfg(target_os = "macos")]
mod secret_manager;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod secrets;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod server;
#[cfg(target_os = "macos")]
mod service;

#[cfg(target_os = "linux")]
#[path = "service_linux.rs"]
mod service;

#[cfg(target_os = "macos")]
mod platform {
    pub use seccy_macos::{MAX_SECRET_BYTES, SecureEnclave as Store, caller};
}
#[cfg(target_os = "linux")]
mod platform {
    pub use seccy_linux::{MAX_SECRET_BYTES, Vault as Store, caller};
}

/// Hardware-backed SSH authentication, Git signing, and secret encryption
#[derive(Cli)]
#[usage(bin = "seccy", version)]
struct App {
    /// Emit JSON (agent emits one object per line)
    #[usage(long, global)]
    json: bool,
    /// Filter the JSON response with a jq expression (overrides --json)
    #[usage(long, global)]
    jq: Option<String>,
    /// Filter JSON with jq, printing string results without quotes
    #[usage(long, global)]
    jq_raw: Option<String>,
    /// Filter JSON with jq; exit 1 for false/null, 4 for no results
    #[usage(long, global)]
    jq_exit_status: Option<String>,
    #[usage(subcommand)]
    command: Commands,
}

#[derive(Subcommands)]
enum Commands {
    /// Manage multi-recipient secrets (macOS Secure Enclave)
    #[usage(alias = "s")]
    Secrets(secret_args::SecretsArgs),
    /// Print shell setup for PATH and SSH_AUTH_SOCK
    Activate(ActivateArgs),
    /// Initialize the Linux TPM/FIDO vault
    Init(InitArgs),
    /// Install or locate the fnox plugin
    Fnox(FnoxArgs),
    /// Idempotently create configured hardware-backed keys
    Provision(Empty),
    /// List registered and user-config keys with their status and source
    List(Empty),
    /// Show information for a registered or user-config key
    Get(KeyArgs),
    /// Write missing or outdated public-key files
    Sync(Empty),
    /// Run the SSH agent in the foreground
    Agent(AgentArgs),
    /// Encrypt stdin with a configured public key (64 KiB maximum)
    Encrypt(KeyArgs),
    /// Decrypt ciphertext from stdin through the running agent
    Decrypt(SecretArgs),
    /// Check the running agent and selected encryption key without a private operation
    CryptoCheck(SecretArgs),
    /// Delete a key from the registry, public files, and Keychain
    Remove(RemoveArgs),
    /// Delete all seccy keys and registry entries; preserve source configs
    Reset(ConfirmArgs),
    /// Manage the per-user login service
    Service(ServiceArgs),
    /// Manage GitHub SSH keys using gh
    Gh(GhArgs),
}

#[derive(Args)]
struct ActivateArgs {
    /// Shell type: bash, elvish, fish, nu, xonsh, zsh, pwsh, powershell (defaults to SHELL)
    shell_type: Option<String>,
}

#[derive(Args)]
struct InitArgs {
    /// Enumerate connected FIDO authenticators without enrolling
    #[usage(long)]
    list: bool,
    /// Device path selected from init --list (used only during enrollment)
    #[usage(long)]
    device: Option<String>,
}

#[derive(Args)]
struct FnoxArgs {
    #[usage(subcommand)]
    command: FnoxCommand,
}

#[derive(Subcommands)]
enum FnoxCommand {
    /// Install or update the embedded plugin in the user data directory
    Init(Empty),
    /// Show the installed plugin directory and provider file
    Info(Empty),
}

#[derive(Args)]
struct GhArgs {
    #[usage(subcommand)]
    command: GhCommand,
}

#[derive(Subcommands)]
enum GhCommand {
    /// Reconcile this machine's GitHub authentication and signing keys
    Sync(GhSyncArgs),
}

#[derive(Args)]
struct GhSyncArgs {
    /// Display the plan and apply without confirmation
    #[usage(short = 'y', long)]
    yes: bool,
    /// Command prefix used to invoke gh (shell-style quoting)
    #[usage(long, default = "gh")]
    cmd: String,
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
            let mut raw_query = None;
            let mut exit_query = None;
            let mut args = argv.iter();
            while let Some(arg) = args.next() {
                if arg == "--" {
                    break;
                }
                if arg == "--jq-exit-status" {
                    exit_query = args.next().and_then(|s| s.to_str());
                } else if let Some(value) = arg
                    .to_str()
                    .and_then(|s| s.strip_prefix("--jq-exit-status="))
                {
                    exit_query = Some(value);
                } else if arg == "--jq-raw" {
                    raw_query = args.next().and_then(|s| s.to_str());
                } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--jq-raw=")) {
                    raw_query = Some(value);
                } else if arg == "--jq" {
                    query = args.next().and_then(|s| s.to_str());
                } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--jq=")) {
                    query = Some(value);
                } else if arg == "--json" {
                    json = true;
                }
            }
            let output = match Output::new(json, query, raw_query, exit_query) {
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
            std::process::exit(if exit.code == 0 {
                output.exit_code()
            } else {
                exit.code
            });
        }
    };
    let output = match Output::new(
        app.json,
        app.jq.as_deref(),
        app.jq_raw.as_deref(),
        app.jq_exit_status.as_deref(),
    ) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    };
    if let Err(error) = run(app, &output) {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if error.is::<gh::CommandFailed>() {
            std::process::exit(1);
        }
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
    std::process::exit(output.exit_code());
}

fn run(app: App, output: &Output) -> Result<()> {
    if let Commands::Activate(args) = &app.command {
        return activate::run(args.shell_type.as_deref(), output);
    }
    logging::init()?;
    if let Commands::Secrets(args) = app.command {
        #[cfg(target_os = "macos")]
        return secret_manager::run(args, output);
        #[cfg(not(target_os = "macos"))]
        {
            let _ = args;
            anyhow::bail!("managed secrets currently require macOS Secure Enclave");
        }
    }
    if let Commands::Fnox(args) = &app.command {
        return match args.command {
            FnoxCommand::Info(_) => fnox::info(output),
            FnoxCommand::Init(_) => fnox::init(output),
        };
    }
    if let Commands::Init(args) = &app.command {
        #[cfg(target_os = "linux")]
        {
            let result = seccy_linux::initialize(args.device.as_deref(), args.list)?;
            let text = if args.list {
                result["devices"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                format!(
                    "Linux vault ready: {}",
                    result["vault"].as_str().unwrap_or_default()
                )
            };
            return output.emit(result, &text);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&args.device, args.list);
            anyhow::bail!("init is only needed on Linux; use provision on macOS");
        }
    }
    let command = match &app.command {
        Commands::Secrets(_) => unreachable!(),
        Commands::Activate(_) => unreachable!(),
        Commands::Init(_) => unreachable!(),
        Commands::Fnox(_) => unreachable!(),
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
        Commands::Gh(_) => "gh",
    };
    let paths = seccy_core::storage::Paths::from_env()?;
    tracing::info!(event = "command_started", command, config = %paths.config.display());
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
        Config::load(&paths.config)?
    };
    run_platform(app, config, output)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn run_platform(_: App, _: Config, _: &Output) -> Result<()> {
    anyhow::bail!("Secure Enclave operations require macOS")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_platform(app: App, config: Config, output: &Output) -> Result<()> {
    use seccy_core::storage::Paths;
    let store = platform::Store;
    let paths = Paths::from_env()?;
    match app.command {
        Commands::Secrets(_) => unreachable!(),
        Commands::Activate(_) => unreachable!(),
        Commands::Init(_) => unreachable!(),
        Commands::Fnox(_) => unreachable!(),
        command @ (Commands::Provision(_)
        | Commands::List(_)
        | Commands::Get(_)
        | Commands::Sync(_)
        | Commands::Remove(_)
        | Commands::Reset(_)) => {
            inventory::run(command, &config, &paths.config, &paths, output)?;
        }
        Commands::Service(args) => service::run(args.command, &paths, output)?,
        Commands::Gh(args) => match args.command {
            GhCommand::Sync(args) => gh::run(args, &config, &paths.config, &paths, output)?,
        },
        Commands::Agent(args) => server::run(args.socket, output)?,
        Commands::Encrypt(args) => {
            use anyhow::Context;
            let _lock = inventory::read_lock(&paths)?;
            let state = inventory::view(&paths, &config, &paths.config)?;
            let identity = state
                .identity(&store, &args.name)?
                .context("key is not provisioned")?;
            let input = secrets::read_stdin(platform::MAX_SECRET_BYTES)?;
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
