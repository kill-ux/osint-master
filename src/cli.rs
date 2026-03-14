use clap::{
    ColorChoice, Parser,
    builder::{
        Styles,
        styling::{AnsiColor, Effects},
    },
};

// const MY_STYLES: Styles = Styles::default();
/// Custom styles for the CLI help message.
const MY_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default());

/// OSINT-Master Tool
/// 
/// A powerful intelligence gathering tool for IPs, usernames, and domains.
#[derive(Parser)]
#[command(name = "osintmaster", version = "1.0.0", arg_required_else_help = true, color = ColorChoice::Always, styles=MY_STYLES)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,

    /// File name to save output.
    #[arg(short,long, global = true)]
    pub output: Option<String>,

    /// Number of concurrent threads for scanning.
    #[arg(short,long, global = true, default_value = "1")]
    pub threads: usize,
}

/// Available subcommands for the OSINT-Master tool.
#[derive(clap::Subcommand)]
pub enum Commands {
    /// Search information by IP address.
    #[command(short_flag = 'i', long_flag = "ip")]
    Ip { 
        /// The IP address or hostname to look up.
        #[arg(value_name = "ADDRESS")]
        address: String 
    },
    
    /// Search information by username.
    #[command(short_flag = 'u', long_flag = "user")]
    User { 
        /// The username to search for across platforms.
        #[arg(value_name = "NAME")]
        name: String 
    },
    
    /// Enumerate subdomains and check for takeover risks.
    #[command(short_flag = 'd', long_flag = "domain")]
    Domain { 
        /// The target domain to scan.
        #[arg(value_name = "URL")]
        name: String 
    },
}