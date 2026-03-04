use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::aws::codeartifact;

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
                println!("Fetching authorization token...");
                let token = codeartifact::get_authorization_token(domain, domain_owner, region)?;
                println!("{}", token);
            }
        },
    }

    Ok(())
}
