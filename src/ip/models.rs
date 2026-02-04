use serde::{Deserialize, Serialize};

pub const IP_API_FIELDS: usize = 454553599;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpReport {
    // Basic Status & Query
    pub status: String,
    pub message: Option<String>,
    pub query: String, // The IP address searched

    #[serde(flatten)]
    pub details: Option<IpDetails>
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpDetails {
    // Location Data
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub region_name: String,
    pub city: String,
    pub zip: String,
    pub lat: f64,
    pub lon: f64,
    pub timezone: String,

    // Network & Infrastructure
    pub isp: String,
    pub org: String,
    pub r#as: String,
    pub asname: Option<String>,
    pub reverse: Option<String>, // Reverse DNS (PTR record)

    // Security & Advanced Intelligence (The "Power" Fields)
    pub mobile: bool,  // Is the user on a cellular network?
    pub proxy: bool,   // Is this a known Proxy, VPN, or Tor node?
    pub hosting: bool, // Is this a Data Center (e.g., AWS/DigitalOcean)?
}
