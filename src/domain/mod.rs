use std::collections::HashMap;

use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose};
use chrono::{DateTime, Utc};
use colored::Colorize;
use dns_lookup::lookup_host;
use reqwest::Client;
use serde::Deserialize;

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
     let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    for (domain, cert) in &subdomains {
        // Resolve THIS subdomain's IP
        let mut info = SubdomainInfo::default();
        info.domain = cert.name_value.clone();
        info.record_type = "NXDOMAIN".to_string();
        info.cert_id = cert.id;

        if let Ok(mut ips) = lookup_host(domain)
            && let Some(ip) = ips.next()
        {
            info.ip = Some(ip.to_string());
            info.record_type = "A".to_string();
        };

        get_cert_details_binary(&mut info).await?;
        check_takeover(&mut info).await;
        domins.push(info);
    }

    // dbg!(&domins);

    Ok(())
}

#[derive(Debug, Default)]
pub struct SubdomainInfo {
    pub domain: String,      // e.g. "www.example.com"
    pub ip: Option<String>,  // e.g. "123.123.123.123"
    pub record_type: String, // e.g. "A" or "CNAME"
    pub issuer: String,
    pub cert_id: u64,
    pub expiry: String,
    pub version: String,
    pub serial: String,
    pub signature: String,
    pub vulnerability: String,
}

pub struct CertDetails {
    pub common_name: String,
    pub sans: Vec<String>,
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

use tracing::warn;
use trust_dns_resolver::{
    Resolver, TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
    error::ResolveErrorKind,
    proto::rr::RecordType,
};
use x509_parser::prelude::*;

pub async fn get_cert_details_binary(info: &mut SubdomainInfo) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("https://crt.sh/?d={}", info.cert_id);
    let raw_data = client.get(url).send().await?.bytes().await?;
    let der_data = if raw_data.starts_with(b"-----BEGIN CERTIFICATE-----") {
        let pem_str = String::from_utf8(raw_data.to_vec())?;
        let bytes = pem_str
            .lines()
            .filter(|line| !line.starts_with("---"))
            .collect::<String>();
        general_purpose::STANDARD.decode(bytes)?
    } else {
        raw_data.to_vec()
    };

    // Parse the DER binary data
    let (_, cert) = X509Certificate::from_der(&der_data)
        .map_err(|_| anyhow::anyhow!("Failed to parse DER for ID {}", info.cert_id))?;

    let tbs = cert.tbs_certificate;

    // Extracting info with precision
    let issuer = tbs.issuer.to_string();
    if let Ok(expiry) = tbs.validity.not_after.to_rfc2822() {
        info.expiry = expiry;
    }

    if let Ok(expiry_date) = DateTime::parse_from_rfc2822(&info.expiry) {
        if expiry_date < Utc::now() {
            info.vulnerability.push_str(" | EXPIRED_CERTIFICATE");
        }
    }

    info.issuer = issuer;

    info.version = tbs.version.to_string();
    info.serial = tbs.serial.to_str_radix(16).to_uppercase();
    info.signature = tbs.signature.algorithm.to_string();
    info.issuer = tbs.issuer.to_string();
    info.expiry = tbs
        .validity
        .not_after
        .to_rfc2822()
        .unwrap_or("".to_string());

    // 2. Check for Weak Signatures (SHA-1 OID is 1.2.840.113549.1.1.5)
    if info.signature == "1.2.840.113549.1.1.5" {
        info.vulnerability.push_str(" | WEAK_SIG_ALGO_SHA1");
    }
    dbg!(info);
    Ok(())
}

pub async fn check_takeover(info: &mut SubdomainInfo) {
    match resolve_cname(info).await {
        Ok(cname) => {
            info.record_type = "CNAME".to_string();
            let vulnerable_providers = ["github.io", "herokuapp", "s3.amazonaws", "azurewebsites"];
            for provider in vulnerable_providers {
                if cname.contains(provider) {
                    // It points to a cloud service. Is that service actually alive?
                    if let Some(_) = &info.ip {
                        info.vulnerability = format!("CRITICAL: Dangling CNAME to {}", provider);
                    }
                }
            }
        }
        Err(dns_err) => {
            warn!("DNS error: {}", dns_err);
        }
    }
}

pub async fn resolve_cname(info: &mut SubdomainInfo) -> Result<String> {
   

    let lookup = match resolver.lookup(&info.domain, RecordType::CNAME).await {
        Ok(lookup) => lookup,
        Err(e) => {
            if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                info.record_type = "DNS_MISSING".to_string();
                info.vulnerability =
                    "Potential Takeover: Domain exists in logs but has no DNS records".to_string();
            }
            bail!("Error: Can't resolve cname".to_string());
        }
    };

    // Return the first CNAME target found
    for record in lookup.iter() {
        if let Some(cname) = record.as_cname() {
            // Convert to string and trim the trailing dot
            return Ok(cname.to_string().trim_end_matches('.').to_string());
        }
    }

    bail!("Error: Can't resolve cname".to_string());
}
