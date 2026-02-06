use anyhow::Result;
use clap::Parser;
use osint_master::{
    Cli, Commands, domain::run_domain_lookup, ip::run_ip_lookup, username::run_username_lookup,
};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt::init();
    match cli.command {
        Commands::Ip { address } => run_ip_lookup(address, cli.output).await,
        Commands::User { name } => run_username_lookup(name, cli.output).await,
        Commands::Domain { name } => run_domain_lookup(name, cli.output).await,
    }?;
    Ok(())
}
