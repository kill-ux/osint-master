use std::{env, sync::Arc};

use anyhow::Result;
use dotenvy::dotenv;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{fs::File, io::AsyncReadExt, sync::Semaphore, task::JoinSet};

use colored::Colorize;

#[derive(Debug, Deserialize, Clone)]
pub struct ProfileField {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Platform {
    pub name: String,
    pub url: String,
    pub pre_url: Option<String>,
    pub platform_type: PlatformType,
    pub not_found_indicators: Vec<String>,
    pub profile_fields: Option<Vec<ProfileField>>,
    pub api_key: Option<String>,
    pub html_extractors: Option<Vec<HtmlExtractor>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HtmlExtractor {
    pub name: String,
    pub pattern: String,
    pub group: Option<usize>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PlatformType {
    Api,
    Web,
}

pub type ProfileData = serde_json::Value;

#[derive(Debug, Serialize)]
pub struct PlatformResult {
    pub url: String,
    pub name: String,
    pub found: bool,
    pub profile: Option<ProfileData>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UsernameReport {
    pub username: String,
    pub total_checked: usize,
    pub total_found: usize,
    pub platforms: Vec<PlatformResult>,
    pub scan_time: String,
}

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
        save_report(&path, &results).await?;
    }

    Ok(())
}

async fn load_platforms() -> Result<Vec<Platform>> {
    let mut file = File::open("platforms.json").await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let platforms: Vec<Platform> = serde_json::from_str(&contents)?;
    Ok(platforms)
}

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
        let pre_url = platform
            .pre_url
            .clone()
            .unwrap_or_else(|| String::new())
            .replace("{username}", &username);
        set.spawn(async move {
            let _permit = semaphore.acquire().await;
            check_platform(&username, &platform, &url, &pre_url, &client).await
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

async fn check_platform(
    username: &str,
    platform: &Platform,
    url: &str,
    pre_url: &str,
    client: &Client,
) -> Result<PlatformResult> {
    println!("  Checking {} on {}...", username, platform.name);

    // Handle different platform types
    match platform.platform_type {
        PlatformType::Api => check_api_platform(username, platform, url, pre_url, client).await,
        PlatformType::Web => check_web_platform(platform, url, client).await,
    }
}

async fn check_pre_url(pre_url: &str, client: &Client) -> Result<Option<String>> {
    let response = client.get(pre_url).send().await?;

    if response.status().is_success() {
        if let Ok(json) = response.json::<serde_json::Value>().await {
            if let Some(steamid) = json.pointer("/response/steamid").and_then(|v| v.as_str()) {
                return Ok(Some(steamid.to_string()));
            }
        }
    }

    Ok(None)
}

async fn check_api_platform(
    username: &str,
    platform: &Platform,
    url: &str,
    pre_url: &str,
    client: &Client,
) -> Result<PlatformResult> {
    let mut api_key = None;
    let mut pre_url = pre_url.to_string();
    let mut url = url.to_string();

    if let Some(api_key_name) = &platform.api_key {
        dotenv().ok(); // Load .env file (consider moving this to main)
        api_key = env::var(api_key_name).ok();
        if let Some(key) = &api_key {
            pre_url = pre_url.replace("{key}", key);
            url = url.replace("{key}", key);
        }
    }

    let mut url = url.to_string();
    if !pre_url.is_empty()
        && let Some(id) = check_pre_url(&pre_url, client).await?
    {
        url = url.replace("{id}", &id);
    }

    let response = client.get(&url).send().await;

    let profile = match response {
        Ok(resp) => {
            let status = resp.status();

            if status.is_success() {
                // Try to parse JSON
                match resp.json::<serde_json::Value>().await {
                    Ok(json)
                        if json != Value::Null
                            && !json.as_object().map_or(false, |o| o.is_empty())
                            && !json.as_array().map_or(false, |o| o.is_empty()) =>
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
                    Err(e) => PlatformResult {
                        url: url.clone(),
                        name: platform.name.clone(),
                        found: true,
                        profile: None,
                        error: Some(format!("Failed to parse JSON: {}", e)),
                    },
                    _ => PlatformResult {
                        url: url.clone(),
                        name: platform.name.clone(),
                        found: false, // ← usually you want false here
                        profile: None,
                        error: Some("Empty or invalid JSON response".to_string()),
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

// check steam if response > playesrs empty
fn check_special_cases(json: &Value) -> bool {
    if let Some(players) = json.pointer("/response/players") {
        return !players.as_array().map_or(false, |o| o.is_empty());
    }
    true
}

async fn check_web_platform(
    platform: &Platform,
    url: &str,
    client: &Client,
) -> Result<PlatformResult> {
    let response = client.get(url).send().await;
    dbg!(&response);
    dbg!(&url);

    match response {
        Ok(resp) => {
            let status = resp.status();
            dbg!(resp.content_length());

            if status.is_success() {
                // Try to read the HTML body
                let html = match resp.text().await {
                    Ok(text) => text,
                    Err(_) => {
                        // Cannot read body – assume found but no data
                        return Ok(PlatformResult {
                            url: url.to_string(),
                            name: platform.name.clone(),
                            found: true,
                            profile: None,
                            error: None,
                        });
                    }
                };

                dbg!(&html);

                // Check if the page indicates "not found"
                let not_found = platform
                    .not_found_indicators
                    .iter()
                    .any(|indicator| html.contains(indicator));

                if not_found {
                    return Ok(PlatformResult {
                        url: url.to_string(),
                        name: platform.name.clone(),
                        found: false,
                        profile: None,
                        error: None,
                    });
                }

                // If extractors are defined, apply them
                let profile = if let Some(extractors) = &platform.html_extractors {
                    let mut extracted = serde_json::Map::new();
                    for ext in extractors {
                        if let Ok(re) = Regex::new(&ext.pattern) {
                            dbg!(&html);
                            if let Some(caps) = re.captures(&html) {
                                dbg!(&caps);
                                let group = ext.group.unwrap_or(1);
                                if let Some(value) = caps.get(group) {
                                    dbg!(
                                        "Extractor '{}' found value: {}",
                                        &ext.name,
                                        value.as_str()
                                    );
                                    extracted.insert(
                                        ext.name.clone(),
                                        serde_json::Value::String(value.as_str().to_string()),
                                    );
                                }
                            }
                        }
                    }
                    if extracted.is_empty() {
                        None
                    } else {
                        Some(serde_json::Value::Object(extracted))
                    }
                } else {
                    None
                };

                Ok(PlatformResult {
                    url: url.to_string(),
                    name: platform.name.clone(),
                    found: true,
                    profile,
                    error: None,
                })
            } else if status == 404 {
                Ok(PlatformResult {
                    url: url.to_string(),
                    name: platform.name.clone(),
                    found: false,
                    profile: None,
                    error: None,
                })
            } else {
                Ok(PlatformResult {
                    url: url.to_string(),
                    name: platform.name.clone(),
                    found: false,
                    profile: None,
                    error: Some(format!("HTTP {}", status)),
                })
            }
        }
        Err(e) => Ok(PlatformResult {
            url: url.to_string(),
            name: platform.name.clone(),
            found: false,
            profile: None,
            error: Some(e.to_string()),
        }),
    }
}

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
                    } else if value.is_number() {
                        println!("     {}: {}", key, value);
                    } else if value.is_boolean() {
                        println!("     {}: {}", key, value);
                    }
                }
            } else {
                println!("     Profile data available");
            }
        }
    }
}

async fn save_report(path: &str, report: &UsernameReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    tokio::fs::write(path, json).await?;
    println!("\n✅ Report saved to: {}", path);
    Ok(())
}
