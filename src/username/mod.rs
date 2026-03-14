use std::{env, sync::Arc};

use anyhow::Result;
use dotenvy::dotenv;
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
    pub pre_process: Option<PreProcess>,
    pub not_found_indicators: Vec<String>,
    pub profile_fields: Option<Vec<ProfileField>>,
    pub api_key: Option<String>,
    pub html_extractors: Option<Vec<HtmlExtractor>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PreProcess {
    pub url: String,
    pub response_path: String,
    pub not_found_indicators: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HtmlExtractor {
    pub name: String,
    pub pattern: String,
    pub group: Option<usize>,
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
        crate::report::save_report(&path, &results).await?;
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

                // Check for not found indicators in the response text
                let is_not_found = platform.not_found_indicators.iter().any(|indicator| text.contains(indicator));

                if is_not_found {
                    return Ok(PlatformResult {
                        url: url.clone(),
                        name: platform.name.clone(),
                        found: false,
                        profile: None,
                        error: None,
                    });
                }

                // Try to parse JSON
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

// check steam if response > playesrs empty
fn check_special_cases(json: &Value) -> bool {
    if let Some(players) = json.pointer("/response/players") {
        return !players.as_array().is_some_and(|o| o.is_empty());
    }
    true
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
