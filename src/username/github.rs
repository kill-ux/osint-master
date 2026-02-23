
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubProfile {
    pub login: String,
    pub name: Option<String>,
    pub company: Option<String>,
    pub location: Option<String>,
    pub email: Option<String>,
    pub bio: Option<String>,
    pub followers: u32,
    pub following: u32,
    pub public_repos: u32,
    pub public_gists: u32,
    pub created_at: String,
    pub updated_at: String,
    pub twitter_username: Option<String>,
    pub blog: Option<String>,
    pub hireable: Option<bool>,
    pub avatar_url: String,
    pub html_url: String,
}

impl GitHubProfile {
    pub async fn check(username: &str, client: &Client) -> Result<Option<Self>> {
        let url = format!("https://api.github.com/users/{}", username);
        
        let response = client
            .get(&url)
            .header("User-Agent", "osint-tool/1.0")
            .timeout(Duration::from_secs(10))
            .send()
            .await?;

        match response.status().as_u16() {
            200 => {
                let profile = response.json::<GitHubProfile>().await?;
                Ok(Some(profile))
            }
            404 => Ok(None),
            status => {
                let text = response.text().await.unwrap_or_default();
                anyhow::bail!("GitHub API error ({}): {}", status, text)
            }
        }
    }

    pub fn to_profile_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "bio": self.bio,
            "followers": self.followers,
            "following": self.following,
            "public_repos": self.public_repos,
            "company": self.company,
            "location": self.location,
            "created_at": self.created_at,
            "profile_url": self.html_url,
            "avatar_url": self.avatar_url
        })
    }
}