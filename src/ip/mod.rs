pub mod dns;
pub mod models;

use anyhow::{Result, bail};
use colored::Colorize;
use comfy_table::{Table, presets::UTF8_FULL};
use reqwest::Client;

use dns::*;
use models::*;
use tokio::{fs::File, io::AsyncWriteExt};

pub async fn run_ip_lookup(target: String, output: Option<String>) -> Result<()> {
    let ip = resolve_target(&target).await?.to_string();
    let ip_str = ip.as_str();
    println!("Searching IP: {}", ip_str);
    let report = fetch_data(ip_str).await?;
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
        dbg!(remaining);
        let ttl = res.headers().get("X-Ttl").and_then(|v| v.to_str().ok());
        if let (Some(rl), Some(ttl)) = (remaining, ttl) {
            tracing::debug!("Requests remaining: {}, reset in {}s", rl, ttl);
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

pub fn print_report(ip: &str, details: &Option<IpDetails>) {
    if let Some(details) = details {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL).set_header(vec![
            "Category".on_magenta().black(),
            "Intelligence".magenta().bold(),
        ]);

        // .cyan() and .bold() work here, but we must convert to String
        table.add_row(vec!["Target IP".cyan(), ip.bold()]);

        table.add_row(vec![
            "Location",
            &format!("{}, {}", details.city, details.country.bold()),
        ]);
        table.add_row(vec!["ISP", &details.isp]);

        let asn_only = details
            .r#as
            .split_whitespace()
            .next()
            .unwrap_or("N/A")
            .replace("AS", "");
        table.add_row(vec!["ASN", &asn_only]);

        let issues = match (details.proxy, details.hosting) {
            (true, _) => "Flagged: Proxy/VPN detected".red().bold().to_string(),
            (_, true) => "Note: Data center/Hosting".yellow().to_string(),
            _ => "✅ No reported abuse (Residential)".green().to_string(),
        };

        // With "custom_styling" enabled, comfy-table will respect the ANSI codes
        table.add_row(vec!["Known Issues", &issues]);

        println!("{table}");
    }
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
    let mut fd = File::create(path).await?;
    fd.write_all(res.as_bytes()).await?;
    println!(
        "💾 {} {}",
        "Data successfully saved to:".green(),
        path.bold()
    );
    Ok(())
}
