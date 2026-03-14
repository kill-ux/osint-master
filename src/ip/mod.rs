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

/// The fields to request from the ip-api.com API.
pub const IP_API_FIELDS: usize = 454553599;

/// Default WHOIS server configuration.
/// |    Part    | Meaning                                                            |
/// |-------------|-------------------------------------------------------------------|
/// |     `n`     | ARIN-specific flag — means "return the most specific record"      |
/// |     `+`     | ARIN flag — return full/verbose output                            |
/// |   `$addr`   | Placeholder — replaced with the actual IP at runtime              |
/// |    `\r\n`   | Carriage return + newline — required by WHOIS protocol (RFC 3912) |
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

/// Performs an IP address lookup and intelligence gathering.
///
/// # Arguments
/// * `target` - The IP address or hostname to look up.
/// * `output` - Optional file path to save the report.
///
/// # Returns
/// * `Result<()>` - Ok if successful, Error otherwise.
pub async fn run_ip_lookup(target: String, output: Option<String>) -> Result<()> {
    dotenv()?;
    let api_key = env::var("ABUSEIPDB_API_KEY").context("API Key not found in .env")?;

    let ip = resolve_target(&target).await?.to_string();
    let ip_str = ip.as_str();
    println!("Searching IP: {}", ip_str);

    let mut report = fetch_data(ip_str).await?;
    let info = fetch_whois(ip_str).await?;

    // Add timestamp
    if let Some(ref mut details) = report.details {
        details.last_updated = Some(chrono::Local::now().to_rfc3339());
    }

    report.additional_data = Some(info);

    if let Ok(abuse_data) = check_abuse_status(&ip, &api_key).await {
        report.abuse_score = Some(abuse_data.abuse_confidence_score);
        report.total_reports = Some(abuse_data.total_reports);
    }

    if let Ok(history) = fetch_historical_data(&ip, &api_key).await
        && !history.is_empty()
    {
        report.historical_data = Some(history);
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

/// Checks the abuse status of an IP address using AbuseIPDB.
///
/// # Arguments
/// * `ip` - The IP address to check.
/// * `api_key` - The AbuseIPDB API key.
///
/// # Returns
/// * `Result<AbuseData>` - Abuse data if successful.
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

/// Fetches general IP information from ip-api.com.
///
/// # Arguments
/// * `ip` - The IP address to look up.
///
/// # Returns
/// * `Result<IpReport>` - The IP report if successful.
pub async fn fetch_data(ip: &str) -> Result<IpReport> {
    fetch_data_with_retry(ip, 3).await
}

/// Fetches WHOIS information for an IP address.
///
/// # Arguments
/// * `ip` - The IP address to look up.
///
/// # Returns
/// * `Result<WhoisInfo>` - Parsed WHOIS information if successful.
pub async fn fetch_whois(ip: &str) -> Result<WhoisInfo> {
    let whois = WhoIs::from_string(SERVERS)?;
    let options = WhoIsLookupOptions::from_string(ip)?;
    let text = whois.lookup(options)?;

    let info = parse_whois(text);

    // println!("WHOIS text:\n{}", text);
    Ok(info)
}

/// Fetches historical abuse reports for an IP address.
///
/// # Arguments
/// * `ip` - The IP address to look up.
/// * `api_key` - The AbuseIPDB API key.
///
/// # Returns
/// * `Result<Vec<models::HistoricalEvent>>` - A list of historical events if successful.
pub async fn fetch_historical_data(
    ip: &str,
    api_key: &str,
) -> Result<Vec<models::HistoricalEvent>> {
    let client = Client::new();
    let url = format!(
        "https://api.abuseipdb.com/api/v2/reports?ipAddress={}&maxAgeInDays=90",
        ip
    );

    let res = client
        .get(&url)
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send()
        .await?;

    if !res.status().is_success() {
        return Ok(vec![]);
    }

    #[derive(serde::Deserialize)]
    struct HistoricalResponse {
        data: HistoricalData,
    }

    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct HistoricalData {
        total: u32,
        page: u32,
        count: u32,
        #[serde(rename = "perPage")]
        per_page: u32,
        #[serde(rename = "lastPage")]
        last_page: u32,
        #[serde(rename = "nextPageUrl")]
        next_page_url: Option<String>,
        #[serde(rename = "previousPageUrl")]
        previous_page_url: Option<String>,
        results: Vec<HistoricalReport>,
    }

    #[derive(serde::Deserialize)]
    struct HistoricalReport {
        #[serde(rename = "reportedAt")]
        reported_at: Option<String>,
        categories: Option<Vec<u32>>,
        comment: Option<String>,
    }

    match res.json::<HistoricalResponse>().await {
        Ok(response) => {
            let events = response
                .data
                .results
                .into_iter()
                .map(|r| models::HistoricalEvent {
                    date: r.reported_at,
                    category: r.categories.map(|cats| {
                        cats.into_iter()
                            .map(|c| c.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    }),
                    comment: r.comment,
                })
                .collect();
            Ok(events)
        }
        Err(_) => Ok(vec![]),
    }
}

/// Fetches IP information with retry logic for rate limits.
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

/// Prints a formatted IP report to the console.
///
/// # Arguments
/// * `report` - The IP report to print.
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
            "{} {}, {}",
            "Location:".cyan().bold(),
            details.city,
            details.country.bold()
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

        // 4. Historical Data
        if let Some(history) = &report.historical_data
            && !history.is_empty()
        {
            println!("{}", "─".repeat(60).bold());
            println!("{}", "HISTORICAL ABUSE REPORTS".cyan().bold());
            println!("{}", "─".repeat(60).bold());
            for (idx, event) in history.iter().enumerate() {
                println!(
                    "{} {}",
                    format!("Report {}:", idx + 1).yellow().bold(),
                    event.date.as_deref().unwrap_or("Unknown date")
                );
                if let Some(category) = &event.category {
                    println!("  Category: {}", category);
                }
                if let Some(comment) = &event.comment {
                    println!("  Comment: {}", comment);
                }
            }
        }

        println!("{}", "─".repeat(60).bold());
    }
}

/// Represents the response from the AbuseIPDB API.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct AbuseResponse {
    /// The data portion of the response.
    pub data: AbuseData,
}

/// Represents abuse information for an IP address.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct AbuseData {
    /// Confidence score of abuse, from 0 to 100.
    #[serde(rename = "abuseConfidenceScore")]
    pub abuse_confidence_score: u32,
    /// Total number of reports for this IP.
    pub total_reports: u32,
}
