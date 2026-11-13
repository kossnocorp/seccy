use std::path::PathBuf;
use usage_rs::{Args, Subcommands};

#[derive(Args)]
pub struct SecretsArgs {
    /// Use only the user secrets.toml
    #[usage(short = 'g', long, global)]
    pub global: bool,
    /// Use only this secrets file
    #[usage(short = 's', long = "secrets", alias = "file", global)]
    pub file: Option<PathBuf>,
    /// Key handle for decryption (SECCY_IDENTITY overrides this; otherwise match automatically)
    #[usage(short = 'i', long, global)]
    pub identity: Option<String>,
    #[usage(subcommand)]
    pub command: SecretsCommand,
}
#[derive(Subcommands)]
pub enum SecretsCommand {
    /// Set an encrypted secret; prompt without terminal echo by default
    Set(SetArgs),
    /// List secret names and recipients without decrypting
    List(crate::Empty),
    /// Decrypt a secret to stdout; JSON uses value_base64
    Get(NameArgs),
    /// Execute a command with secrets in its environment; use -- before command
    #[usage(alias = "x")]
    Exec(ExecArgs),
    /// Enroll an existing prompt key for managed secrets and add its public recipient
    Enroll(EnrollArgs),
    /// Re-encrypt active-file secrets to the current recipients, atomically
    Reencrypt(RecipientsArgs),
    /// Re-enter one or all active-file secrets and atomically encrypt to selected recipients
    Reset(ResetSecretsArgs),
    /// Remove a secret from the active file
    Remove(NameArgs),
    /// Manage public recipients
    Recipients(RecipientArgs),
}
#[derive(Args)]
pub struct SetArgs {
    pub name: Option<String>,
    #[usage(long)]
    pub from_file: Option<PathBuf>,
    #[usage(long)]
    pub from_stdin: bool,
    /// Recipient alias; repeat to select several (defaults to all)
    #[usage(long, var)]
    pub recipient: Vec<String>,
}
#[derive(Args)]
pub struct RecipientsArgs {
    #[usage(long, var)]
    pub recipient: Vec<String>,
}
#[derive(Args)]
pub struct NameArgs {
    pub name: String,
}
#[derive(Args)]
pub struct ExecArgs {
    /// Optional secret names followed by -- and the command with arguments
    pub args: Vec<String>,
}
#[derive(Args)]
pub struct EnrollArgs {
    pub key: Option<String>,
    /// Alias for the public recipient (defaults to local key name)
    #[usage(long)]
    pub name: Option<String>,
}
#[derive(Args)]
pub struct RecipientArgs {
    #[usage(subcommand)]
    pub command: RecipientCommand,
}
#[derive(Subcommands)]
pub enum RecipientCommand {
    List(crate::Empty),
    Add(AddRecipientArgs),
    Remove(NameArgs),
}
#[derive(Args)]
pub struct AddRecipientArgs {
    pub name: String,
    pub public_key: String,
}

#[derive(Args)]
pub struct ResetSecretsArgs {
    /// Existing secret name; omit to reset every secret in the active file
    pub name: Option<String>,
    /// Read the replacement from an environment variable (requires a secret name)
    #[usage(long)]
    pub from_env: Option<String>,
    /// Replacement recipient aliases (required; repeat for multiple recipients)
    #[usage(long, var)]
    pub recipient: Vec<String>,
    /// Skip replacement confirmation; values are still prompted without echo
    #[usage(short = 'y', long)]
    pub yes: bool,
}
