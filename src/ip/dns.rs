use std::net::IpAddr;

use anyhow::{Context, Result, anyhow};
use tokio::net::lookup_host;

/// Resolves a target string (IP address or hostname) to an IP address.
/// 
/// If the input is already an IP address, it is returned as is.
/// If the input is a hostname, it is resolved to its first IP address.
/// 
/// # Arguments
/// * `input` - The target string to resolve.
/// 
/// # Returns
/// * `Result<IpAddr>` - The resolved IP address on success.
pub async fn resolve_target(input: &str) -> Result<IpAddr> {
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(ip);
    }

    println!("🌐 Hostname detected, resolving {}...", input);

    let mut addr = lookup_host(format!("{}:80", input))
        .await
        .context("Could not resolve hostname: ")?;

    addr.next()
        .map(|socket| socket.ip())
        .ok_or_else(|| anyhow!("No IP addresses found for {}", input))
}



// Usage
