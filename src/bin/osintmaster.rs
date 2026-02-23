use std::process::exit;

use anyhow::{Context, Result};
use clap::Parser;
use osint_master::{
    Cli, Commands,
    domain::{
        enumerate_subdomains, run_domain_lookup,
        takeover::{self, run_domain_lookup_sslmate},
    },
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
            match run_domain_lookup_sslmate(name.clone(), cli.output.clone(), 50).await {
                Err(_) => run_domain_lookup(name.clone(), cli.output, 1).await,
                _ => Ok(()),
            }
        }
    }?;
    Ok(())
}
