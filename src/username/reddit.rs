use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedditProfile {
    pub username: String,
    pub created_utc: u64,
    pub total_karma: u64,
    pub link_karma: u64,
    pub comment_karma: u64,
    pub followers: u64,
    pub bio: Option<String>,
    pub is_gold: bool,
    pub is_mod: bool,
    pub avatar: Option<String>,
    pub profile_url: String,
}

pub async fn check_reddit(username: &str, client: &Client) -> Result<Option<RedditProfile>> {
    let url = format!("https://www.reddit.com/user/{}/about.json", username);
    let response = client
        .get(&url)
        .header("User-Agent", "osint-tool/1.0")
        .send()
        .await?;

    if response.status().as_u16() == 404 {
        return Ok(None);
    }
    if !response.status().is_success() {
        anyhow::bail!("Reddit API error: {}", response.status());
    }

    let json: serde_json::Value = response.json().await?;

    // Extract fields with defaults where missing
    let username = json
        .pointer("/data/name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let created_utc = json
        .pointer("/data/created_utc")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0) as u64;

    let total_karma = json
        .pointer("/data/total_karma")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let link_karma = json
        .pointer("/data/link_karma")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let comment_karma = json
        .pointer("/data/comment_karma")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let followers = json
        .pointer("/data/subreddit/subscribers")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let bio = json
        .pointer("/data/subreddit/public_description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    let is_gold = json
        .pointer("/data/is_gold")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let is_mod = json
        .pointer("/data/is_mod")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let avatar = json
        .pointer("/data/icon_img")
        .and_then(|v| v.as_str())
        .map(|s| s.split('?').next().unwrap_or(s).to_string()); // clean URL

    let profile_url = format!("https://www.reddit.com/user/{}", username);

    Ok(Some(RedditProfile {
        username,
        created_utc,
        total_karma,
        link_karma,
        comment_karma,
        followers,
        bio,
        is_gold,
        is_mod,
        avatar,
        profile_url,
    }))
}