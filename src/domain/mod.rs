use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use colored::Colorize;
use dns_lookup::lookup_host;
use openssl::ssl::{SslConnector, SslMethod};
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

#[derive(Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
struct CrtShEntry {
    name_value: String,
    id: u64,
    #[serde(with = "crt_sh_date_format")]
    not_after: DateTime<Utc>,
}
pub async fn run_ctr_sh(target: &str) -> Result<()> {
    let client = Client::new();
    let url = format!("https://crt.sh/?q=.{}&output=json", target);
    let res = client.get(url).send().await?;

    if !res.status().is_success() {
        return Err(anyhow::anyhow!(
            "API returned error status: {}",
            res.status()
        ));
    }

    let certs: Vec<CrtShEntry> = res.json().await?;
    let mut subdomains = HashMap::new();

    // Parse subdomains first
    for cert in &certs {
        for name in cert.name_value.split_whitespace() {
            let clean_name = name.trim_start_matches("*.").to_string();
            if !clean_name.is_empty() && clean_name.ends_with(target) {
                let mut new_cert = cert.clone();
                new_cert.name_value = clean_name.clone();
                subdomains.insert(clean_name.clone(), new_cert);
            }
        }
    }

    // NOW resolve each subdomain individually
    let mut domins: Vec<SubdomainInfo> = Vec::new();
    for (domain, cert) in &subdomains {
        // Resolve THIS subdomain's IP
        match lookup_host(domain) {
            Ok(mut ips) => {
                if let Some(ip) = ips.next() {
                    domins.push(SubdomainInfo {
                        domain: cert.name_value.clone(),
                        ip: Some(ip.to_string()),
                        record_type: "A".to_string(),
                    });
                }
            }
            Err(_) => {
                domins.push(SubdomainInfo {
                    domain: cert.name_value.clone(),
                    ip: None,
                    record_type: "NXDOMAIN".to_string(),
                });
            }
        }

        // Get CERT
        let clt = reqwest::Client::new();
        let url = format!("https://crt.sh/?id={}&opt=x509dump", cert.id);
        let res = clt.get(url).send().await?;
        if res.status().is_success() {
            let text = res.text().await?;
            // dbg!(&text);
            parse_dump_for_info(&text);
        } else {
            warn!("Failed to fetch cert dump for ID {}", cert.id);
        }
    }

    dbg!(&domins);

    // Print results
    println!(
        "\n{} Found {} subdomains",
        "✅".green().bold(),
        domins.len()
    );
    for info in &domins {
        match &info.ip {
            Some(ip) => println!("  {} → {}", info.domain.blue().bold(), ip),
            None => println!("  {} → {}", info.domain.blue().bold(), "no IP".red()),
        }
    }

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

// pub fn check_cert(hostname: &str) -> Result<()> {
//     let connector = SslConnector::builder(SslMethod::tls())?
//         .use_rustls(false) // force OpenSSL
//         .build();
//     Ok(())
// }

mod crt_sh_date_format {
    use chrono::{DateTime, NaiveDateTime, Utc};
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // Try parsing as NaiveDateTime first (no timezone)
        match NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S") {
            Ok(naive_dt) => Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc)),
            Err(_) => {
                // Also try with fractional seconds
                let without_fraction = s.split('.').next().unwrap_or(&s);
                NaiveDateTime::parse_from_str(without_fraction, "%Y-%m-%dT%H:%M:%S")
                    .map(|naive_dt| DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc))
                    .map_err(|_| {
                        serde::de::Error::custom(format!("Failed to parse datetime: {}", s))
                    })
            }
        }
    }
}

fn parse_dump_for_info(dump: &str) -> (String, String) {
    let mut issuer = "Unknown".to_string();
    let mut expiry = "Unknown".to_string();

    for line in dump.lines() {
        dbg!(line);
        let line = line.trim();
        if line.contains("Issuer:") {
            issuer = line.replace("Issuer:", "").trim().to_string();
        } else if line.contains("Not After :") {
            expiry = line.replace("Not After :", "").trim().to_string();
        }
    }
    (issuer, expiry)
}
