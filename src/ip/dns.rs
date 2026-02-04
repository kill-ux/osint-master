use std::net::IpAddr;

use anyhow::{Context, Result, anyhow};
use tokio::net::lookup_host;

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
