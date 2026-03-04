use anyhow::Context;
use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::aws::codeartifact;
use crate::aws::sso;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(subcommand)]
    Codeartifact(CodeArtifactCommands),
}

#[derive(Debug, Subcommand)]
enum CodeArtifactCommands {
    GetAuthorizationToken {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        domain_owner: String,
        #[arg(long)]
        region: Option<String>,
    },
}

pub fn execute() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Codeartifact(cmd) => match cmd {
            CodeArtifactCommands::GetAuthorizationToken {
                domain,
                domain_owner,
                region,
            } => {
                log::debug!(
                    "CodeArtifact - Get authorization token for domain '{}'",
                    domain
                );

                let (credentials, region) = match sso::get_credentials_from_env() {
                    Some(env_credentials) => {
                        (env_credentials, region.context("No region provided")?)
                    }
                    None => {
                        let sso_config = sso::get_config_from_profile()
                            .context("Failed to get SSO config from profile")?;
                        let temp_credentials = sso::get_temp_credentials(&sso_config)?;
                        let region = region.unwrap_or(sso_config.region.clone());
                        (temp_credentials, region)
                    }
                };

                let token = codeartifact::request_codeartifact_token(
                    &credentials,
                    &region,
                    &domain,
                    &domain_owner,
                )
                .context("Failed to get CodeArtifact token")?;
                println!("{}", token);
            }
        },
    }

    Ok(())
}
