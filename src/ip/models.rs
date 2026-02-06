use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpReport {
    // Basic Status & Query
    pub status: String,
    pub message: Option<String>,
    pub query: String, // The IP address searched

    #[serde(flatten)]
    pub details: Option<IpDetails>,
    pub additional_data: Option<WhoisInfo>,
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

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct WhoisInfo {
    pub org_name: Option<String>,
    pub country: Option<String>,
    pub abuse_email: Option<String>,
    pub abuse_phone: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub net_range: Option<String>,
    pub cidr: Option<String>,
    pub address: Option<String>,
}

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
