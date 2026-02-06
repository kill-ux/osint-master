use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use anyhow::Result;
use colored::Colorize;
use dns_lookup::lookup_host;
use reqwest::Client;
use serde::Deserialize;
use tracing::warn;

pub async fn run_domain_lookup(target: String, _output: Option<String>) -> Result<()> {
    println!("Searching Domain: {}", target);
    println!(
        "\n{}{}",
        " Main Domain: ".on_magenta().black().bold(),
        target.on_bright_blue().black().bold()
    );
    println!("{}", "─".repeat(60).bold());
    run_ctr_sh(&target).await?;

    Ok(())
}

#[derive(Deserialize, Debug)]
struct CrtShEntry {
    name_value: String,
}

pub async fn run_ctr_sh(target: &str) -> Result<()> {
    let client = Client::new();
    let url = format!("https://crt.sh/?q=.{}&output=json", target);
    let res = client.get(url).send().await?;
    let ip = lookup_host(target)?.next().map(|arg| arg.to_string());
    if !res.status().is_success() {
        return Err(anyhow::anyhow!(
            "API returned error status: {}",
            res.status()
        ));
    }
    let certs: Vec<CrtShEntry> = res.json().await?;
    let mut subdomains = HashSet::new();
    for cert in &certs {
        let mut tab = cert
            .name_value
            .trim()
            .trim_start_matches("*.")
            .split_whitespace();
        while let Some(name) = tab.next() {
            subdomains.insert(name);
        }
    }
    dbg!(&subdomains);
    let mut domins = vec![];
    for hostname in &subdomains {
        domins.push(SubdomainInfo {domain: hostname.to_string(),ip: ip.clone(),record_type: "".to_string() });
        // let ip = resolve_target(d).await?.to_string();
    }
    dbg!(&domins);

    Ok(())
}

#[derive(Debug)]
pub struct SubdomainInfo {
    pub domain: String,      // e.g. "www.example.com"
    pub ip: Option<String>,  // e.g. "123.123.123.123"
    pub record_type: String, // e.g. "A" or "CNAME"
}

pub struct CertDetails {
    pub common_name: String,
    pub sans: Vec<String>,
    pub issuer: String,
    pub expiry: String,
}


pub fn get_detailed_cert(ip: &str)  {
    
}