pub mod dns;
pub mod models;

use std::path::Path;

use anyhow::{Result, bail};
use colored::Colorize;
use reqwest::Client;

use dns::*;
use models::*;
use tokio::{
    fs::{File, create_dir_all},
    io::AsyncWriteExt,
};
use tracing::warn;
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
    let ip = resolve_target(&target).await?.to_string();
    let ip_str = ip.as_str();
    println!("Searching IP: {}", ip_str);
    let mut report = fetch_data(ip_str).await?;
    let text = fetch_whois(ip_str).await?;
    let info = parse_whois(text);
    report.additional_data = Some(info);
    print_report(&report.query, &report.details);
    if let Some(ref path) = output {
        save_report(path, &report).await?;
    }
    println!(
        "\n{}\n",
        " IP ANALYSIS COMPLETED ".on_magenta().black().bold()
    );
    Ok(())
}

pub async fn fetch_data(ip: &str) -> Result<IpReport> {
    fetch_data_with_retry(ip, 3).await
}

pub async fn fetch_whois(ip: &str) -> Result<String> {
    let whois = WhoIs::from_string(SERVERS)?;
    let options = WhoIsLookupOptions::from_string(ip)?;
    let text = whois.lookup(options)?;
    // println!("WHOIS text:\n{}", text);
    Ok(text)
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


pub async fn save_report(path: &str, report: &models::IpReport) -> Result<()> {
    let res = if path.ends_with("json") {
        serde_json::to_string_pretty(report)?
    } else {
        serde_txtrecord::to_txt_records(report)?
            .into_iter()
            .map(|(key, value)| format!("{}: {}", key.to_uppercase(), value))
            .collect::<Vec<String>>()
            .join("\n")
    };
    let path = Path::new(path);
    if let Some(parent) = path.parent()
        && parent.to_str() != Some("")
    {
        warn!("Directory dosn't exist will be created");
        create_dir_all(parent).await?;
    }
    let mut fd = File::create(path).await?;
    fd.write_all(res.as_bytes()).await?;
    println!(
        "{} {}",
        "Data successfully saved to:".green(),
        Path::new(path).to_string_lossy()
    );
    Ok(())
}

pub fn print_report(ip: &str, details: &Option<IpDetails>) {
    if let Some(details) = details {
        println!("{}", "─".repeat(60).bold());
        println!("{} {}", "TARGET IP:".cyan().bold(), ip.bold());
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
    }
}
