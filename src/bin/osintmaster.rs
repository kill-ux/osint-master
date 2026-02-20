use std::process::exit;

use anyhow::{Context, Result};
use clap::Parser;
use osint_master::{
    Cli, Commands,
    domain::{SubdomainScanner, enumeration, run_domain_lookup, takeover},
    ip::run_ip_lookup,
    username::run_username_lookup,
};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt::init();
    match cli.command {
        Commands::Ip { address } => run_ip_lookup(address, cli.output).await,
        Commands::User { name } => run_username_lookup(name, cli.output).await,
        Commands::Domain { name } => {
            dotenvy::dotenv().ok();
            let token = std::env::var("CENSYS_API_TOKEN")
                .context("CENSYS_API_TOKEN not found in .env file")?;

            let scanner = SubdomainScanner::new(token, name);

            let results = scanner.enumerate(1).await?;
            exit(0)
        }
    }?;
    Ok(())
}
