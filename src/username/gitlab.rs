use std::time::Duration;

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabProfile {
    pub username: String,
    pub id: u64,
    pub name: Option<String>,
    pub public_email: Option<String>,
    pub state: String,
    pub locked: bool,
    pub avatar_url: String,
    pub web_url: String,
}

impl GitLabProfile {
    pub async fn check(username: &str, client: &Client) -> Result<Option<Self>> {
        let url = format!("https://gitlab.com/api/v4/users?username={}", username);
        
        let response = client
            .get(&url)
            .header("User-Agent", "osint-tool/1.0")
            .timeout(Duration::from_secs(10))
            .send()
            .await?;

        match response.status().as_u16() {
            200 => {
                let users = response.json::<Vec<GitLabProfile>>().await?;
                Ok(users.into_iter().next())
            }
            404 => Ok(None),
            status => {
                let text = response.text().await.unwrap_or_default();
                anyhow::bail!("GitLab API error ({}): {}", status, text)
            }
        }
    }

    pub fn to_profile_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "public_email": self.public_email,
            "state": self.state,
            "locked": self.locked,
            "profile_url": self.web_url,
            "avatar_url": self.avatar_url
        })
    }
}