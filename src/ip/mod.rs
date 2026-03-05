pub mod dns;
pub mod models;

use std::env;

use anyhow::{Context, Result, bail};
use colored::Colorize;
use dotenvy::dotenv;
use reqwest::Client;

use dns::*;
use models::*;
use whois_rust::{WhoIs, WhoIsLookupOptions};

pub const IP_API_FIELDS: usize = 454553599;

const SERVERS: &str = r#"
        {
            "_": {
                "ip": {
                    "host": "whois.arin.net",
                    "query": "n + $addr\r\n"
                }
            }
        }
    "#;

pub async fn run_ip_lookup(target: String, output: Option<String>) -> Result<()> {
    dotenv()?;
    let api_key = env::var("ABUSEIPDB_API_KEY").context("API Key not found in .env")?;

    let ip = resolve_target(&target).await?.to_string();
    let ip_str = ip.as_str();
    println!("Searching IP: {}", ip_str);

    let mut report = fetch_data(ip_str).await?;
    let info = fetch_whois(ip_str).await?;
    report.additional_data = Some(info);

    if let Ok(abuse_data) = check_abuse_status(&ip, &api_key).await {
        report.abuse_score = Some(abuse_data.abuse_confidence_score);
        report.total_reports = Some(abuse_data.total_reports);
    }

    print_report(&report);
    if let Some(ref path) = output {
        crate::report::save_report(path, &report).await?;
    }

    println!(
        "\n{}\n",
        " IP ANALYSIS COMPLETED ".on_magenta().black().bold()
    );
    Ok(())
}

pub async fn check_abuse_status(ip: &str, api_key: &str) -> Result<AbuseData> {
    let client = reqwest::Client::new();
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={}", ip);

    let res = client
        .get(url)
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send()
        .await?;

    if !res.status().is_success() {
        bail!("AbuseIPDB Error: {}", res.status());
    }

    let json: AbuseResponse = res.json().await?;
    Ok(json.data)
}

pub async fn fetch_data(ip: &str) -> Result<IpReport> {
    fetch_data_with_retry(ip, 3).await
}

pub async fn fetch_whois(ip: &str) -> Result<WhoisInfo> {
    let whois = WhoIs::from_string(SERVERS)?;
    let options = WhoIsLookupOptions::from_string(ip)?;
    let text = whois.lookup(options)?;

    let info = parse_whois(text);

    // println!("WHOIS text:\n{}", text);
    Ok(info)
}

async fn fetch_data_with_retry(ip: &str, max_retries: u32) -> Result<IpReport> {
    let client = Client::new();
    let url = format!("http://ip-api.com/json/{}?fields={}", ip, IP_API_FIELDS);

    for _ in 0..=max_retries {
        let res = client.get(&url).send().await?;
        if res.status() == 429 {
            let ttl = res.headers().get("X-Ttl").and_then(|v| v.to_str().ok());
            if let Some(ttl) = ttl.and_then(|s| s.parse::<u64>().ok()) {
                tokio::time::sleep(tokio::time::Duration::from_secs(ttl)).await;
            }
            continue;
        }

        if !res.status().is_success() {
            return Err(anyhow::anyhow!(
                "API returned error status: {}",
                res.status()
            ));
        }

        let remaining = res.headers().get("X-Rl").and_then(|v| v.to_str().ok());
        let ttl = res.headers().get("X-Ttl").and_then(|v| v.to_str().ok());
        if let (Some(rl), Some(ttl)) = (remaining, ttl) {
            tracing::warn!("Requests remaining: {}, reset in {}s", rl, ttl);
        }

        let report: IpReport = res.json().await?;
        if report.status.as_str() == "fail" {
            bail!(
                "API Error: {}",
                report.message.unwrap_or("Unknown error".to_string())
            );
        }

        return Ok(report);
    }

    bail!("Failed after {} retries", max_retries)
}

pub fn print_report(report: &IpReport) {
    if let Some(details) = &report.details {
        println!("{}", "─".repeat(60).bold());
        println!("{} {}", "TARGET IP:".cyan().bold(), report.query.bold());
        println!("{}", "─".repeat(60).bold());

        // 1. Critical / risk‑related info first
        let issues = match (details.proxy, details.hosting) {
            (true, _) => "Flagged: Proxy/VPN detected".red().bold(),
            (_, true) => "Note: Data center/Hosting".yellow(),
            _ => "✅ No reported abuse (Residential)".green(),
        };
        println!("{} {}", "RISK PROFILE:".cyan().bold(), issues);

        println!(
            "{} {}",
            "ASN:".cyan().bold(),
            details
                .r#as
                .split_whitespace()
                .next()
                .unwrap_or("N/A")
                .replace("AS", "")
                .bold()
        );

        println!("{} {}", "ISP:".cyan().bold(), details.isp.bold());

        // 2. Location
        println!(
            "{} {}",
            "Location:".cyan().bold(),
            format!("{}, {}", details.city, details.country.bold())
        );

        println!("{} {}", "Region:".cyan().bold(), details.region_name.bold());
        println!("{} {}", "Timezone:".cyan().bold(), details.timezone.bold());

        // 3. Extra flags
        println!(
            "{} {}",
            "Mobile:".cyan().bold(),
            if details.mobile {
                "Yes".red().bold()
            } else {
                "No".green()
            }
        );

        println!("{}", "─".repeat(60).bold());

        let score = report.abuse_score.unwrap_or(0);
        let risk_status = if score > 75 {
            format!("HIGH RISK ({}%)", score).red().bold()
        } else if score > 25 {
            format!("MEDIUM RISK ({}%)", score).yellow()
        } else {
            format!("CLEAN ({}%)", score).green()
        };

        println!("{} {}", "ABUSE SCORE:".cyan().bold(), risk_status);
        println!(
            "{} {}",
            "REPORTS:".cyan().bold(),
            report.total_reports.unwrap_or(0)
        );
        println!("{}", "─".repeat(60).bold());
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct AbuseResponse {
    pub data: AbuseData,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct AbuseData {
    #[serde(rename = "abuseConfidenceScore")]
    pub abuse_confidence_score: u32,
    #[serde(rename = "totalReports")]
    pub total_reports: u32,
    pub domain: Option<String>,
    pub usage_type: Option<String>,
}
