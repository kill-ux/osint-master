use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use colored::Colorize;
use dns_lookup::lookup_host;
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use reqwest::{Client, header::AUTHORIZATION};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::{File, create_dir_all},
    io::AsyncWriteExt,
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tracing::warn;
use trust_dns_resolver::{
    AsyncResolver, TokioAsyncResolver,
    error::{ResolveError, ResolveErrorKind},
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
    proto::rr::RecordType,
};

const VULNERABLE_PROVIDERS: &[(&str, &str, &str)] = &[
    // Cloud Platforms
    ("AWS S3", "s3.amazonaws.com", "NoSuchBucket"),
    (
        "AWS CloudFront",
        "cloudfront.net",
        "ERROR: The request could not be satisfied",
    ),
    ("Azure", "azurewebsites.net", "404 Site Not Found"),
    ("Azure", "cloudapp.net", "404 Site Not Found"),
    ("Azure", "trafficmanager.net", "404 Site Not Found"),
    ("Google Cloud", "storage.googleapis.com", "NoSuchBucket"),
    ("Digital Ocean", "digitaloceanspaces.com", "NoSuchBucket"),
    ("Heroku", "herokuapp.com", "no such app"),
    ("Heroku SSL", "herokussl.com", "no such app"),
    (
        "GitHub Pages",
        "github.io",
        "There isn't a GitHub Pages site here",
    ),
    ("Fastly", "fastly.net", "Fastly error: unknown domain"),
    ("Netlify", "netlify.app", "Not Found - Request ID:"),
    ("Vercel", "vercel.app", "404: NOT_FOUND"),
    ("Firebase", "firebaseapp.com", "404. That's an error."),
    ("Surge", "surge.sh", "project not found"),
    // SaaS Platforms
    ("WordPress.com", "wordpress.com", "Do you want to register"),
    (
        "Shopify",
        "myshopify.com",
        "Sorry, this shop is currently unavailable",
    ),
    ("Wix", "wixsite.com", "404 - Page Not Found"),
    ("Squarespace", "squarespace.com", "404 - Page Not Found"),
    ("Tumblr", "tumblr.com", "There's nothing here"),
    (
        "Ghost",
        "ghost.io",
        "The thing you were looking for is no longer here",
    ),
    ("Readme.io", "readme.io", "Project doesn't exist"),
    // Marketing
    (
        "Unbounce",
        "unbouncepages.com",
        "The page you were looking for doesn't exist",
    ),
    (
        "Campaign Monitor",
        "createsend.com",
        "The specified campaign does not exist",
    ),
    (
        "GetResponse",
        "getresponse.com",
        "The page you are looking for does not exist",
    ),
    // Support
    ("Zendesk", "zendesk.com", "Help Center Closed"),
    (
        "Freshdesk",
        "freshdesk.com",
        "The page you were looking for does not exist",
    ),
    (
        "Help Scout",
        "helpscoutdocs.com",
        "We couldn't find the page you were looking for",
    ),
    // Development
    (
        "ReadTheDocs",
        "readthedocs.io",
        "The page you're looking for doesn't exist",
    ),
    ("Ngrok", "ngrok.io", "Tunnel *.ngrok.io not found"),
    // Project Management
    ("Trello", "trello.com", "Board not found"),
    (
        "Asana",
        "asana.com",
        "The page you were looking for doesn't exist",
    ),
    (
        "Canny",
        "canny.io",
        "The page you were looking for does not exist",
    ),
    (
        "Aha!",
        "aha.io",
        "The page you are looking for cannot be found",
    ),
];

pub type Res = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

// ==================== DATA STRUCTURES ====================

#[derive(Debug, Default, Serialize, Clone)]
pub struct SubdomainInfo {
    pub domain: String,
    pub ip: Option<String>,
    pub record_type: String,
    pub issuer: String,
    pub cert_id: u64,
    pub expiry: String,
    pub version: String,
    pub serial: String,
    pub signature: String,
    pub vulnerability: String,
}

// ==================== SSLMATE API STRUCTS ====================

#[derive(Debug, Deserialize, Clone)]
struct CertSpotterIssuance {
    id: String,
    dns_names: Option<Vec<String>>,
    not_before: String,
    not_after: String,
    issuer: Option<IssuerInfo>,
    revoked: Option<bool>,
    #[serde(default)]
    revocation: Option<RevocationInfo>,
    #[serde(default)]
    pubkey: Option<PubKeyInfo>,
    cert_der: Option<String>,
    tbs_sha256: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct IssuerInfo {
    friendly_name: String,
    name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct RevocationInfo {
    #[serde(default, deserialize_with = "deserialize_reason")]
    reason: Option<String>,
    #[serde(default)]
    time: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct PubKeyInfo {
    #[serde(rename = "type")]
    key_type: String,
    bit_length: Option<i32>,
}

// Custom deserializer for revocation reason
fn deserialize_reason<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Visitor;
    use std::fmt;

    struct ReasonVisitor;

    impl<'de> Visitor<'de> for ReasonVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("null, integer, or string")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
            let reason = match value {
                0 => "Unspecified".to_string(),
                1 => "Key Compromise".to_string(),
                2 => "CA Compromise".to_string(),
                3 => "Affiliation Changed".to_string(),
                4 => "Superseded".to_string(),
                5 => "Cessation of Operation".to_string(),
                6 => "Certificate Hold".to_string(),
                8 => "Remove from CRL".to_string(),
                9 => "Privilege Withdrawn".to_string(),
                10 => "AA Compromise".to_string(),
                _ => format!("Unknown reason code: {}", value),
            };
            Ok(Some(reason))
        }

        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
            self.visit_i64(value as i64)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(value.to_string()))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
            Ok(Some(value))
        }
    }

    deserializer.deserialize_any(ReasonVisitor)
}

// ==================== SSLMATE CLIENT ====================

pub struct SSLMateClient {
    client: Client,
    api_key: String,
}

impl SSLMateClient {
    pub fn new(api_key: String) -> Result<Self> {
        let client = Client::builder().timeout(Duration::from_secs(15)).build()?;
        Ok(Self { client, api_key })
    }

    async fn get_issuances(&self, domain: &str) -> Result<Vec<CertSpotterIssuance>> {
        let encoded = percent_encode(domain.as_bytes(), NON_ALPHANUMERIC).to_string();

        let url = format!(
            "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names&expand=issuer&expand=pubkey&expand=revocation",
            encoded
        );

        let response = self
            .client
            .get(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("SSLMate API error ({}): {}", status, text);
        }

        let issuances: Vec<CertSpotterIssuance> = response.json().await?;
        Ok(issuances)
    }
}

// ==================== DNS RESOLVER ====================

pub async fn resolve_domain(domain: &str) -> Result<Vec<String>> {
    match timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking({
            let domain = domain.to_string();
            move || lookup_host(&domain)
        }),
    )
    .await
    {
        Ok(Ok(Ok(ips))) => Ok(ips.map(|ip| ip.to_string()).collect()),
        _ => Ok(vec![]),
    }
}

// ==================== TAKEOVER CHECK ====================

pub async fn check_takeover(info: &mut SubdomainInfo, resolver: &Res) {
    match resolve_cname(info, resolver).await {
        Ok(cname) => {
            info.record_type = "CNAME".to_string();
            for (service, pattern, _fingerprint) in VULNERABLE_PROVIDERS {
                if cname.contains(pattern) && info.ip.is_none() {
                    add_vuln(info, &format!("CRITICAL: Dangling CNAME to {}", service));
                    break;
                }
            }
        }
        Err(dns_err) => {
            if let Some(err) = dns_err.downcast_ref::<ResolveError>()
                && matches!(err.kind(), ResolveErrorKind::NoRecordsFound { .. })
            {
                info.record_type = "DNS_MISSING".to_string();
                add_vuln(
                    info,
                    "Potential Takeover: Domain exists in logs but has no DNS records",
                );
            } else {
                warn!("DNS error: {}", dns_err);
            }
        }
    }
}

pub async fn resolve_cname(info: &mut SubdomainInfo, resolver: &Res) -> Result<String> {
    let lookup = resolver.lookup(&info.domain, RecordType::CNAME).await?;
    for record in lookup.iter() {
        if let Some(cname) = record.as_cname() {
            return Ok(cname.to_string().trim_end_matches('.').to_string());
        }
    }
    bail!("Error: Can't resolve cname".to_string());
}

// ==================== HELPER FUNCTIONS ====================

fn add_vuln(info: &mut SubdomainInfo, msg: &str) {
    if info.vulnerability.is_empty() {
        info.vulnerability = msg.to_string();
    } else {
        info.vulnerability.push_str(&format!(" | {}", msg));
    }
}

// ==================== MAIN ENUMERATION FUNCTION ====================

pub async fn enumerate_subdomains(
    domain: &str,
    sslmate_key: &str,
    threads: usize,
) -> Result<Vec<SubdomainInfo>> {
    println!("Searching Domain: {}", domain);
    println!(
        "\n{}{}",
        " Main Domain: ".on_magenta().black().bold(),
        domain.on_bright_blue().black().bold()
    );
    println!("{}", "─".repeat(60).bold());

    // Initialize client
    let sslmate = SSLMateClient::new(sslmate_key.to_string())?;

    // Get all issuances
    let issuances = sslmate.get_issuances(domain).await?;

    // Build a map of domain to certificate info
    let mut domain_to_certs: HashMap<String, Vec<CertSpotterIssuance>> = HashMap::new();
    let mut all_subdomains = HashSet::new();

    for issuance in &issuances {
        if let Some(dns_names) = &issuance.dns_names {
            for name in dns_names {
                let clean_name = name.trim_start_matches("*.").to_string();
                if clean_name.ends_with(domain) {
                    domain_to_certs
                        .entry(clean_name.clone())
                        .or_insert_with(Vec::new)
                        .push(issuance.clone());

                    if clean_name != domain {
                        all_subdomains.insert(clean_name);
                    }
                }
            }
        }
    }

    // Add the main domain
    all_subdomains.insert(domain.to_string());

    // Resolve each subdomain with concurrency control
    println!("\nResolving subdomains...");
    let mut domain_to_ips: HashMap<String, Vec<String>> = HashMap::new();
    let mut set = JoinSet::new();
    let semaphore = Arc::new(Semaphore::new(threads));

    for subdomain in all_subdomains.clone() {
        let permit = semaphore.clone();

        set.spawn(async move {
            let _permit = permit.acquire().await;
            let ips = resolve_domain(&subdomain).await.unwrap_or_default();
            (subdomain, ips)
        });
    }

    while let Some(res) = set.join_next().await {
        if let Ok((subdomain, ips)) = res {
            if !ips.is_empty() {
                domain_to_ips.insert(subdomain, ips);
            }
            print!(".");
        }
    }
    println!();

    // Build results
    let mut results = Vec::new();

    for subdomain in all_subdomains {
        let certs = domain_to_certs.get(&subdomain).cloned().unwrap_or_default();
        let ips = domain_to_ips.get(&subdomain).cloned().unwrap_or_default();

        // Find the latest cert for this domain
        let latest_cert = certs.into_iter().max_by(|a, b| {
            let a_date = DateTime::parse_from_rfc3339(&a.not_after).unwrap_or_default();
            let b_date = DateTime::parse_from_rfc3339(&b.not_after).unwrap_or_default();
            a_date.cmp(&b_date)
        });

        if let Some(cert) = latest_cert {
            // Parse expiry
            let expiry = DateTime::parse_from_rfc3339(&cert.not_after).unwrap_or_default();
            let now = Utc::now();
            let expiry_rfc2822 = expiry.to_rfc2822();

            // Determine record type and vulnerabilities
            let (record_type, mut vulnerability) = if ips.is_empty() {
                (
                    "DNS_MISSING".to_string(),
                    "Potential Takeover: Domain exists in logs but has no DNS records".to_string(),
                )
            } else {
                ("A".to_string(), String::new())
            };

            // Add expiry vulnerability
            if expiry < now {
                if !vulnerability.is_empty() {
                    vulnerability += " | EXPIRED_CERTIFICATE";
                } else {
                    vulnerability = "EXPIRED_CERTIFICATE".to_string();
                }
            }

            // Extract certificate details
            let serial = cert.tbs_sha256.unwrap_or_else(|| "Unknown".to_string());
            let cert_id = cert.id.parse::<u64>().unwrap_or(0);

            let issuer = cert
                .issuer
                .as_ref()
                .map(|i| i.name.clone().unwrap_or_else(|| i.friendly_name.clone()))
                .unwrap_or_else(|| "Unknown".to_string());

            let signature = if let Some(pubkey) = &cert.pubkey {
                if pubkey.key_type == "ecdsa" {
                    format!("ecdsa (P-256)") // or extract actual curve from cert
                } else {
                    format!("{} {}", pubkey.key_type, pubkey.bit_length.unwrap_or(0))
                }
            } else {
                "Unknown".to_string()
            };

            // Check for weak signature
            if signature.contains("sha1") || signature.contains("SHA1") {
                if !vulnerability.is_empty() {
                    vulnerability += " | WEAK_SIGNATURE_SHA1";
                } else {
                    vulnerability = "WEAK_SIGNATURE_SHA1".to_string();
                }
            }

            // Create entries
            if !ips.is_empty() {
                for ip in ips {
                    results.push(SubdomainInfo {
                        domain: subdomain.clone(),
                        ip: Some(ip),
                        record_type: record_type.clone(),
                        issuer: issuer.clone(),
                        cert_id,
                        expiry: expiry_rfc2822.clone(),
                        version: "V3".to_string(),
                        serial: serial.clone(),
                        signature: signature.clone(),
                        vulnerability: vulnerability.clone(),
                    });
                }
            } else {
                results.push(SubdomainInfo {
                    domain: subdomain.clone(),
                    ip: None,
                    record_type,
                    issuer,
                    cert_id,
                    expiry: expiry_rfc2822,
                    version: "V3".to_string(),
                    serial,
                    signature,
                    vulnerability,
                });
            }
        }
    }

    // Sort results
    results.sort_by(|a, b| a.domain.cmp(&b.domain));

    Ok(results)
}

// ==================== REPORT GENERATION ====================

pub fn print_report(results: &[SubdomainInfo]) {
    println!(
        "\n{} {}",
        "✔".green().bold(),
        format!("Subdomains found: {}", results.len()).bold()
    );

    let mut vulnerabilities = Vec::new();

    for info in results {
        let status_icon = if info.ip.is_some() {
            "●".green()
        } else {
            "○".red()
        };

        println!(
            "  {} {} ({})",
            status_icon,
            info.domain.bright_white().bold(),
            info.ip.as_deref().unwrap_or("No IP").dimmed()
        );

        if !info.expiry.is_empty() {
            if info.vulnerability.contains("EXPIRED") {
                println!("    {} {}", "▓ SSL:".yellow(), info.expiry.red());
            } else {
                println!("    {} {}", "▓ SSL:".cyan(), info.expiry.dimmed());
            }
        }

        if !info.vulnerability.is_empty() {
            vulnerabilities.push(info.clone());
        }
    }

    if !vulnerabilities.is_empty() {
        println!(
            "\n{}",
            "❗ Potential Vulnerabilities & Risks:"
                .on_red()
                .black()
                .bold()
        );
        for vuln in vulnerabilities {
            println!("  → {}", vuln.domain.bright_white());
            println!("    {}", vuln.vulnerability.yellow().italic());
        }
    }
}

pub async fn save_report(path: &str, results: &[SubdomainInfo]) -> Result<()> {
    let res = if path.ends_with("json") {
        serde_json::to_string_pretty(results)?
    } else {
        // Simple text format as fallback
        results
            .iter()
            .map(|r| format!("{}: {}", r.domain, r.ip.as_deref().unwrap_or("No IP")))
            .collect::<Vec<String>>()
            .join("\n")
    };

    let path = Path::new(path);
    if let Some(parent) = path.parent()
        && parent.to_str() != Some("")
    {
        create_dir_all(parent).await?;
    }

    let mut fd = File::create(path).await?;
    fd.write_all(res.as_bytes()).await?;
    println!(
        "{} {}",
        "Data successfully saved to:".green(),
        path.to_string_lossy()
    );
    Ok(())
}

// ==================== MAIN FUNCTION ====================

pub async fn run_domain_lookup_sslmate(
    target: String,
    output: Option<String>,
    threads: usize,
) -> Result<()> {
    dotenvy::dotenv().ok();

    let sslmate_key =
        std::env::var("SSLMATE_API_KEY").expect("SSLMATE_API_KEY not found in .env file");

    let results = enumerate_subdomains(&target, &sslmate_key, threads).await?;

    print_report(&results);

    if let Some(path) = output {
        save_report(&path, &results).await?;
    }

    Ok(())
}
