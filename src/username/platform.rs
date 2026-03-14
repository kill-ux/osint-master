use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::{fs::File, io::AsyncReadExt};

/// Represents the result of checking a single platform for a username.
#[derive(Debug, Serialize)]
pub struct PlatformResult {
    /// The URL that was checked.
    pub url: String,
    /// The name of the platform.
    pub name: String,
    /// Whether the username was found on the platform.
    pub found: bool,
    /// Extracted profile data if the user was found.
    pub profile: Option<ProfileData>,
    /// Any error message encountered during the check.
    pub error: Option<String>,
}

/// Type alias for profile data as a JSON value.
pub type ProfileData = serde_json::Value;



/// Represents a platform to check for a username.
#[derive(Debug, Deserialize, Clone)]
pub struct Platform {
    /// The name of the platform.
    pub name: String,
    /// The URL pattern for the profile, with `{username}` as a placeholder.
    pub url: String,
    /// Optional URL to check before the main profile URL.
    pub pre_url: Option<String>,
    /// Optional pre-processing steps before the main check.
    pub pre_process: Option<PreProcess>,
    /// A list of strings that indicate the user was not found if present in the response.
    pub not_found_indicators: Vec<String>,
    /// Optional list of fields to extract from the profile data.
    pub profile_fields: Option<Vec<ProfileField>>,
    /// Optional name of the environment variable containing the API key.
    pub api_key: Option<String>,
}

/// Represents pre-processing steps for a platform check.
#[derive(Debug, Deserialize, Clone)]
pub struct PreProcess {
    /// The URL for the pre-processing request.
    pub url: String,
    /// The JSON pointer path to the ID in the response.
    pub response_path: String,
    /// Indicators that the pre-processing request failed to find the user.
    pub not_found_indicators: Vec<String>,
}

/// Represents a field in a profile to be extracted from JSON data.
#[derive(Debug, Deserialize, Clone)]
pub struct ProfileField {
    /// The display name of the field.
    pub name: String,
    /// The JSON pointer path to the field's value.
    pub path: String,
}



/// Loads platform definitions from the `platforms.json` file.
/// 
/// # Returns
/// * `Result<Vec<Platform>>` - A list of platforms on success.
pub async fn load_platforms() -> Result<Vec<Platform>> {
    let mut file = File::open("platforms.json").await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let platforms: Vec<Platform> = serde_json::from_str(&contents)?;
    Ok(platforms)
}
