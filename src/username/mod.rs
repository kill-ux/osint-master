use std::{env, sync::Arc};

use anyhow::Result;
use dotenvy::dotenv;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use tokio::{sync::Semaphore, task::JoinSet};

use colored::Colorize;

use crate::username::platform::{Platform, PlatformResult, PreProcess, load_platforms};
pub mod platform;

/// Represents a full report of username lookup results across all platforms.
#[derive(Debug, Serialize)]
pub struct UsernameReport {
    /// The username being searched.
    pub username: String,
    /// Total number of platforms checked.
    pub total_checked: usize,
    /// Total number of platforms where the username was found.
    pub total_found: usize,
    /// Detailed results for each platform.
    pub platforms: Vec<PlatformResult>,
    /// The timestamp when the scan was completed.
    pub scan_time: String,
}

/// Performs a username lookup across multiple platforms.
///
/// # Arguments
/// * `username` - The username to search for.
/// * `output` - Optional file path to save the results.
///
/// # Returns
/// * `Result<()>` - Ok if successful, Error otherwise.
pub async fn run_username_lookup(username: String, output: Option<String>) -> Result<()> {
    println!("Searching Username: {}", username);

    // Load platforms from JSON file
    let platforms = load_platforms().await?;
    println!("Loaded {} platforms to check", platforms.len());

    // Create HTTP client with custom headers
    let client = Client::builder()
        .user_agent("osint-tool/1.0")
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // Scan all platforms concurrently
    let results = scan_platforms(&username, platforms, client).await?;

    // Print results
    print_report(&results);

    // Save to file if output specified
    if let Some(path) = output {
        crate::report::save_report(&path, &results).await?;
    }

    Ok(())
}

/// Scans all provided platforms for a username concurrently.
///
/// # Arguments
/// * `username` - The username to scan.
/// * `platforms` - A list of platforms to check.
/// * `client` - The HTTP client to use.
///
/// # Returns
/// * `Result<UsernameReport>` - The aggregated report on success.
async fn scan_platforms(
    username: &str,
    platforms: Vec<Platform>,
    client: Client,
) -> Result<UsernameReport> {
    let client = Arc::new(client);
    let semaphore = Arc::new(Semaphore::new(10)); // Limit concurrent requests
    let mut set = JoinSet::new();

    for platform in platforms {
        let client = client.clone();
        let semaphore = semaphore.clone();
        let username = username.to_string();
        let url = platform.url.replace("{username}", &username);
        let pre_process = platform.pre_process.clone().map(|mut o| {
            o.url = o.url.replace("{username}", &username);
            o
        });
        set.spawn(async move {
            let _permit = semaphore.acquire().await;
            check_api_platform(&platform, &url, &client, pre_process).await
        });
    }

    let mut results = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Ok(platform_result)) = res {
            results.push(platform_result);
        }
    }

    // Sort: found platforms first, then by name
    results.sort_by(|a, b| match (a.found, b.found) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.cmp(&b.name),
    });

    let total_found = results.iter().filter(|r| r.found).count();

    Ok(UsernameReport {
        username: username.to_string(),
        total_checked: results.len(),
        total_found,
        platforms: results,
        scan_time: chrono::Utc::now().to_rfc3339(),
    })
}

/// Performs a pre-processing request to get a user ID for a platform.
///
/// # Arguments
/// * `pre_process` - The pre-processing configuration.
/// * `client` - The HTTP client to use.
///
/// # Returns
/// * `Result<Option<String>>` - The extracted ID if successful.
async fn check_pre_url(pre_process: PreProcess, client: &Client) -> Result<Option<String>> {
    let response = client.get(pre_process.url).send().await?;

    if response.status().is_success()
        && let Ok(json) = response.json::<serde_json::Value>().await
        && let Some(steamid) = json
            .pointer(&pre_process.response_path)
            .and_then(|v| v.as_str())
    {
        return Ok(Some(steamid.to_string()));
    }

    Ok(None)
}

/// Checks a single platform's API for a username.
///
/// # Arguments
/// * `platform` - The platform configuration.
/// * `url` - The URL to check.
/// * `client` - The HTTP client to use.
/// * `pre_process` - Optional pre-processing configuration.
///
/// # Returns
/// * `Result<PlatformResult>` - The result of the platform check.
async fn check_api_platform(
    platform: &Platform,
    url: &str,
    client: &Client,
    pre_process: Option<PreProcess>,
) -> Result<PlatformResult> {
    let mut pre_process = pre_process.clone();
    let mut url = url.to_string();

    if let Some(api_key_name) = &platform.api_key {
        dotenv().ok();
        if let Ok(key) = env::var(api_key_name) {
            if let Some(p) = pre_process.as_mut() {
                p.url = p.url.replace("{key}", &key);
            }

            url = url.replace("{key}", &key);
        }
    }

    if let Some(p) = pre_process
        && let Some(id) = check_pre_url(p, client).await?
    {
        url = url.replace("{id}", &id);
    }

    let response = client.get(&url).send().await;

    let profile = match response {
        Ok(resp) => {
            let status = resp.status();

            if status.is_success() {
                let text = resp.text().await.unwrap_or_default();

                let is_not_found = platform
                    .not_found_indicators
                    .iter()
                    .any(|indicator| text.contains(indicator));

                if is_not_found {
                    return Ok(PlatformResult {
                        url: url.clone(),
                        name: platform.name.clone(),
                        found: false,
                        profile: None,
                        error: None,
                    });
                }

                match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(json)
                        if json != Value::Null
                            && !json.as_object().is_some_and(|o| o.is_empty())
                            && !json.as_array().is_some_and(|o| o.is_empty()) =>
                    {
                        if !check_special_cases(&json) {
                            return Ok(PlatformResult {
                                url: url.clone(),
                                name: platform.name.clone(),
                                found: false,
                                profile: None,
                                error: Some("Special case check failed".to_string()),
                            });
                        }
                        // If there are profile_fields defined, extract them
                        let profile = if let Some(fields) = &platform.profile_fields {
                            let mut extracted = serde_json::Map::new();
                            for field in fields {
                                if let Some(value) = json.pointer(&field.path) {
                                    extracted.insert(field.name.clone(), value.clone());
                                }
                            }
                            if extracted.is_empty() {
                                None
                            } else {
                                Some(serde_json::Value::Object(extracted))
                            }
                        } else {
                            // No fields specified, return the whole JSON
                            Some(json)
                        };

                        PlatformResult {
                            url: url.clone(),
                            name: platform.name.clone(),
                            found: true,
                            profile,
                            error: None,
                        }
                    }
                    Ok(_) => PlatformResult {
                        url: url.clone(),
                        name: platform.name.clone(),
                        found: false, // Empty JSON treated as not found
                        profile: None,
                        error: None,
                    },
                    Err(_) => PlatformResult {
                        url: url.clone(),
                        name: platform.name.clone(),
                        found: true, // Non-JSON response treated as found
                        profile: None,
                        error: None,
                    },
                }
            } else if status == 404 || status == 403 {
                PlatformResult {
                    url: url.clone(),
                    name: platform.name.clone(),
                    found: false,
                    profile: None,
                    error: None,
                }
            } else {
                PlatformResult {
                    url: url.clone(),
                    name: platform.name.clone(),
                    found: false,
                    profile: None,
                    error: Some(format!("HTTP {}", status)),
                }
            }
        }
        Err(e) => PlatformResult {
            url: url.clone(),
            name: platform.name.clone(),
            found: false,
            profile: None,
            error: Some(e.to_string()),
        },
    };
    Ok(profile)
}

/// Checks special cases in JSON responses for certain platforms (e.g., Steam).
///
/// # Arguments
/// * `json` - The JSON value to check.
///
/// # Returns
/// * `bool` - True if the special case check passes, false otherwise.
fn check_special_cases(json: &Value) -> bool {
    if let Some(players) = json.pointer("/response/players") {
        return !players.as_array().is_some_and(|o| o.is_empty());
    }
    true
}

/// Prints a formatted report of the username lookup results to the console.
///
/// # Arguments
/// * `report` - The username lookup report to print.
fn print_report(report: &UsernameReport) {
    println!("\n{}", "═".repeat(80).bright_blue());
    println!(
        "🔍 USERNAME SCAN RESULTS: {}",
        report.username.bright_white().bold()
    );
    println!("{}", "═".repeat(80).bright_blue());
    println!(
        "Found on {}/{} platforms",
        report.total_found.to_string().bright_green().bold(),
        report.total_checked
    );
    println!("{}", "─".repeat(80).dimmed());

    for result in &report.platforms {
        let icon = if result.found {
            "YES ⣿⣿".green()
        } else {
            "NO  ⣿⣿".red()
        };
        println!("\n  {} {}", icon, result.name.bright_white().bold());
        println!("     URL: {}", result.url.dimmed());

        if let Some(error) = &result.error {
            println!("     ⚠️  Error: {}", error.yellow());
        }

        if let Some(profile) = &result.profile {
            if let Some(obj) = profile.as_object() {
                for (key, value) in obj {
                    if let Some(s) = value.as_str() {
                        if !s.is_empty() && s.len() < 50 {
                            println!("     {}: {}", key, s.dimmed());
                        } else if !s.is_empty() {
                            println!("     {}: {}...", key, &s[..47].dimmed());
                        }
                    } else if value.is_number() || value.is_boolean() {
                        println!("     {}: {}", key, value);
                    }
                }
            } else {
                println!("     Profile data available");
            }
        }
    }
}
