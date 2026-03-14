use serde::{Deserialize, Serialize};

/// Represents a historical event or report for an IP address.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HistoricalEvent {
    /// The date of the event.
    pub date: Option<String>,
    /// The category of the event (e.g., "abuse").
    pub category: Option<String>,
    /// A comment or description of the event.
    pub comment: Option<String>,
}

/// Represents a comprehensive report for an IP address.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpReport {
    /// Basic status of the request (e.g., "success" or "fail").
    pub status: String,
    /// Optional error message.
    pub message: Option<String>,
    /// The IP address that was searched.
    pub query: String, // The IP address searched

    /// Detailed information about the IP address.
    #[serde(flatten)]
    pub details: Option<IpDetails>,
    /// Additional information from WHOIS lookups.
    pub additional_data: Option<WhoisInfo>,

    /// Abuse confidence score from AbuseIPDB.
    pub abuse_score: Option<u32>,
    /// Total number of reports from AbuseIPDB.
    pub total_reports: Option<u32>,
    /// Historical report data.
    pub historical_data: Option<Vec<HistoricalEvent>>,
}

/// Detailed geographical and network information for an IP address.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpDetails {
    /// Country name.
    pub country: String,
    /// ISO country code.
    pub country_code: String,
    /// Region code.
    pub region: String,
    /// Region name.
    pub region_name: String,
    /// City name.
    pub city: String,
    /// Zip or postal code.
    pub zip: String,
    /// Latitude coordinate.
    pub lat: f64,
    /// Longitude coordinate.
    pub lon: f64,
    /// Timezone.
    pub timezone: String,

    /// Internet Service Provider name.
    pub isp: String,
    /// Organization name.
    pub org: String,
    /// Autonomous System (AS) number and name.
    pub r#as: String,
    /// AS name.
    pub asname: Option<String>,
    /// Reverse DNS record (PTR).
    pub reverse: Option<String>, // Reverse DNS (PTR record)

    /// Whether the IP is on a mobile network.
    pub mobile: bool,  // Is the user on a cellular network?
    /// Whether the IP is a known proxy, VPN, or Tor node.
    pub proxy: bool,   // Is this a known Proxy, VPN, or Tor node?
    /// Whether the IP is hosted in a data center.
    pub hosting: bool, // Is this a Data Center (e.g., AWS/DigitalOcean)?

    /// Timestamp of the last update to this information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,
}

/// Information extracted from WHOIS records.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct WhoisInfo {
    /// Organization name.
    pub org_name: Option<String>,
    /// Country.
    pub country: Option<String>,
    /// Abuse contact email.
    pub abuse_email: Option<String>,
    /// Abuse contact phone.
    pub abuse_phone: Option<String>,
    /// State or province.
    pub state: Option<String>,
    /// Postal code.
    pub postal_code: Option<String>,
    /// Network range.
    pub net_range: Option<String>,
    /// CIDR block.
    pub cidr: Option<String>,
    /// Physical address.
    pub address: Option<String>,
}

/// Parses raw WHOIS text into a `WhoisInfo` struct.
/// 
/// # Arguments
/// * `text` - The raw WHOIS response text.
/// 
/// # Returns
/// * `WhoisInfo` - The parsed information.
pub fn parse_whois(text: String) -> WhoisInfo {
    let mut info = WhoisInfo::default();
    for ele in text.lines() {
        let line = ele.trim().to_lowercase().to_string();
        let mut value = None;
        if line.contains(":") {
            value = Some(
                ele.trim()
                    .split(":")
                    .nth(1)
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            )
        }
        if line.starts_with("orgname:") || line.starts_with("netname:") {
            info.org_name = value
        } else if line.starts_with("country:") {
            info.country = value
        } else if line.starts_with("orgtechemail:") || line.starts_with("e-mail:") {
            info.abuse_email = value
        } else if line.starts_with("orgabusephone:") || line.starts_with("phone:") {
            info.abuse_phone = value
        } else if line.starts_with("stateprov:") {
            info.state = value
        } else if line.starts_with("postalcode:") {
            info.postal_code = value
        } else if line.starts_with("netrange:") || line.starts_with("inetnum:") {
            info.net_range = value
        } else if line.starts_with("cidr:") || line.starts_with("route:") {
            info.cidr = value
        } else if line.starts_with("address:") {
            if let Some(address) = info.address {
                info.address = Some(format!("{address} || {}", value.unwrap()))
            } else {
                info.address = value
            }
        }
    }
    info
}