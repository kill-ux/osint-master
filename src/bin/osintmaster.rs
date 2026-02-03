use anyhow::Result;
use clap::Parser;
use osint_master::{Cli, Commands, domain, ip, username};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Ip { address } => ip::run_ip_lookup(address, cli.output).await,
        Commands::User { name } => username::run(name, cli.output).await,
        Commands::Domain { name } => domain::run(name, cli.output).await,
    }?;
    Ok(())
}
