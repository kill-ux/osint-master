use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use colored::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs::{File, create_dir_all},
    io::AsyncWriteExt,
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

// ==================== DATA STRUCTURES ====================

#[derive(Debug, Default, Serialize, Clone)]
pub struct AssetInfo {
    // Domain Info
    pub domain: String,
    pub asset_type: String, // "domain", "subdomain", "ip"

    // Network Info
    pub ip: Option<String>,
    pub ports: Vec<u16>,
    pub services: Vec<ServiceInfo>,

    // Certificate Info
    pub certificate: Option<CertificateInfo>,

    // Security Issues
    pub vulnerabilities: Vec<String>,
    pub takeover_risk: Option<TakeoverRisk>,

    // Metadata
    pub location: Option<Location>,
    pub asn: Option<String>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct ServiceInfo {
    pub port: u16,
    pub service_name: String,
    pub transport: String,
    pub banner: Option<String>,
    pub http_info: Option<HttpInfo>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct HttpInfo {
    pub status_code: Option<u16>,
    pub server: Option<String>,
    pub title: Option<String>,
    pub technologies: Vec<String>,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct CertificateInfo {
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    pub key_algorithm: String,
    pub key_size: Option<i32>,
    pub serial: String,
    pub version: i32,
    pub subject_alt_names: Vec<String>,
    pub is_expired: bool,
    pub expires_soon: bool,
    pub is_trusted: bool,
    pub validation_level: String, // DV, OV, EV
}

#[derive(Debug, Serialize, Clone)]
pub struct TakeoverRisk {
    pub risk_level: RiskLevel,
    pub service_type: String,
    pub cname_target: Option<String>,
    pub reason: String,
    pub remediation: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct Location {
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

// ==================== CENSYS API STRUCTS ====================

#[derive(Debug, Deserialize)]
struct CensysSearchResponse<T> {
    result: CensysResult<T>,
}

#[derive(Debug, Deserialize)]
struct CensysResult<T> {
    hits: Vec<T>,
    total: u64,
}

#[derive(Debug, Deserialize)]
struct CensysCertificate {
    #[serde(rename = "parsed")]
    parsed: ParsedCertificate,
    #[serde(rename = "metadata")]
    metadata: CertificateMetadata,
}

#[derive(Debug, Deserialize)]
struct ParsedCertificate {
    #[serde(rename = "validity_period")]
    validity: ValidityPeriod,
    #[serde(rename = "issuer_dn")]
    issuer: String,
    #[serde(rename = "subject_dn")]
    subject: String,
    #[serde(rename = "fingerprint_sha256")]
    fingerprint: String,
    #[serde(rename = "signature_algorithm")]
    signature_algorithm: SignatureAlgorithm,
    #[serde(rename = "subject_key_info")]
    subject_key_info: SubjectKeyInfo,
    #[serde(rename = "extensions")]
    extensions: Extensions,
    #[serde(rename = "serial_number")]
    serial_number: String,
    version: i32,
    #[serde(rename = "names")]
    names: Option<Vec<String>>,
    #[serde(rename = "validation_level")]
    validation_level: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidityPeriod {
    #[serde(rename = "not_before")]
    not_before: String,
    #[serde(rename = "not_after")]
    not_after: String,
}

#[derive(Debug, Deserialize)]
struct SignatureAlgorithm {
    name: String,
    oid: String,
}

#[derive(Debug, Deserialize)]
struct SubjectKeyInfo {
    #[serde(rename = "key_algorithm")]
    key_algorithm: KeyAlgorithm,
    #[serde(rename = "rsa")]
    rsa: Option<RsaInfo>,
    #[serde(rename = "ec")]
    ec: Option<EcInfo>,
}

#[derive(Debug, Deserialize)]
struct KeyAlgorithm {
    name: String,
}

#[derive(Debug, Deserialize)]
struct RsaInfo {
    #[serde(rename = "modulus")]
    modulus: String,
    #[serde(rename = "length")]
    length: i32,
}

#[derive(Debug, Deserialize)]
struct EcInfo {
    #[serde(rename = "curve")]
    curve: String,
    #[serde(rename = "length")]
    length: i32,
}

#[derive(Debug, Deserialize)]
struct Extensions {
    #[serde(rename = "subject_alt_name")]
    subject_alt_name: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CertificateMetadata {
    #[serde(rename = "seen_in_scan")]
    seen_in_scan: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CensysHost {
    ip: String,
    #[serde(rename = "location")]
    location: Option<HostLocation>,
    #[serde(rename = "autonomous_system")]
    autonomous_system: Option<AutonomousSystem>,
    services: Option<Vec<HostService>>,
}

#[derive(Debug, Deserialize)]
struct HostLocation {
    country: Option<String>,
    city: Option<String>,
    coordinates: Option<HostCoordinates>,
}

#[derive(Debug, Deserialize)]
struct HostCoordinates {
    latitude: f64,
    longitude: f64,
}

#[derive(Debug, Deserialize)]
struct AutonomousSystem {
    asn: Option<i32>,
    name: Option<String>,
    country_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HostService {
    port: u16,
    service_name: String,
    transport_protocol: String,
    #[serde(rename = "http")]
    http: Option<HostHttp>,
    certificate: Option<String>,
    banner: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HostHttp {
    response: Option<HttpResponse>,
}

#[derive(Debug, Deserialize)]
struct HttpResponse {
    status_code: Option<u16>,
    headers: Option<HashMap<String, String>>,
    body: Option<String>,
    title: Option<String>,
    server: Option<String>,
    #[serde(rename = "html_title")]
    html_title: Option<String>,
}

// ==================== CENSYS CLIENT ====================

struct CensysClient {
    client: Client,
    token: String,
}

impl CensysClient {
    fn new(token: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            token,
        }
    }

    async fn search_certificates(
        &self,
        query: &str,
        per_page: usize,
    ) -> Result<Vec<CensysCertificate>> {
        let url = "https://search.censys.io/api/v2/certificates/search";

        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "q": query,
                "per_page": per_page,
                "sort": "parsed.validity.not_after:desc"
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error = response.text().await.unwrap_or_default();
            bail!("Censys API error ({}): {}", status, error);
        }

        let data: CensysSearchResponse<CensysCertificate> = response.json().await?;
        Ok(data.result.hits)
    }

    async fn search_hosts(&self, query: &str, per_page: usize) -> Result<Vec<CensysHost>> {
        let url = "https://search.censys.io/api/v2/hosts/search";

        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "q": query,
                "per_page": per_page,
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error = response.text().await.unwrap_or_default();
            bail!("Censys API error ({}): {}", status, error);
        }

        let data: CensysSearchResponse<CensysHost> = response.json().await?;
        Ok(data.result.hits)
    }

    async fn get_host(&self, ip: &str) -> Result<CensysHost> {
        let url = format!("https://search.censys.io/api/v2/hosts/{}", ip);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await?;

        if !response.status().is_success() {
            bail!("Censys API error: {}", response.status());
        }

        #[derive(Debug, Deserialize)]
        struct HostResponse {
            result: CensysHost,
        }

        let data: HostResponse = response.json().await?;
        Ok(data.result)
    }

    pub async fn get_certificate_by_fingerprint(&self, fingerprint: &str) -> Result<CensysCertificate> {
        let url = format!(
            "https://search.censys.io/api/v2/certificates/{}",
            fingerprint
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            bail!("Censys API error ({}): {}", status, error_text);
        }

        #[derive(Debug, Deserialize)]
        struct CertificateResponse {
            result: CensysCertificate,
        }

        let data: CertificateResponse = response.json().await?;
        Ok(data.result)
    }
}

// ==================== TAKEOVER SIGNATURES ====================

struct TakeoverSignature {
    service: &'static str,
    cname_patterns: &'static [&'static str],
    fingerprint: &'static str,
    risk: RiskLevel,
    remediation: &'static str,
}

const TAKEOVER_SIGNATURES: &[TakeoverSignature] = &[
    TakeoverSignature {
        service: "GitHub Pages",
        cname_patterns: &["github.io"],
        fingerprint: "There isn't a GitHub Pages site here",
        risk: RiskLevel::Critical,
        remediation: "Remove CNAME record or create the GitHub Pages site",
    },
    TakeoverSignature {
        service: "Heroku",
        cname_patterns: &["herokuapp.com", "herokussl.com"],
        fingerprint: "no such app",
        risk: RiskLevel::Critical,
        remediation: "Remove CNAME record or recreate the Heroku app",
    },
    TakeoverSignature {
        service: "AWS S3",
        cname_patterns: &["s3.amazonaws.com", "s3-website"],
        fingerprint: "NoSuchBucket",
        risk: RiskLevel::Critical,
        remediation: "Remove CNAME record or recreate the S3 bucket",
    },
    TakeoverSignature {
        service: "Azure",
        cname_patterns: &["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
        fingerprint: "404 Site Not Found",
        risk: RiskLevel::Critical,
        remediation: "Remove CNAME record or recreate the Azure resource",
    },
    TakeoverSignature {
        service: "CloudFront",
        cname_patterns: &["cloudfront.net"],
        fingerprint: "ERROR: The request could not be satisfied",
        risk: RiskLevel::Critical,
        remediation: "Remove CNAME record or reconfigure CloudFront distribution",
    },
    TakeoverSignature {
        service: "Fastly",
        cname_patterns: &["fastly.net"],
        fingerprint: "Fastly error: unknown domain",
        risk: RiskLevel::Critical,
        remediation: "Remove CNAME record or reconfigure Fastly service",
    },
    TakeoverSignature {
        service: "WordPress.com",
        cname_patterns: &["wordpress.com"],
        fingerprint: "Do you want to register",
        risk: RiskLevel::High,
        remediation: "Remove CNAME record or recreate the WordPress.com site",
    },
    TakeoverSignature {
        service: "Shopify",
        cname_patterns: &["myshopify.com"],
        fingerprint: "Sorry, this shop is currently unavailable",
        risk: RiskLevel::High,
        remediation: "Remove CNAME record or recreate the Shopify store",
    },
    TakeoverSignature {
        service: "Surge.sh",
        cname_patterns: &["surge.sh"],
        fingerprint: "project not found",
        risk: RiskLevel::High,
        remediation: "Remove CNAME record or redeploy to Surge",
    },
    TakeoverSignature {
        service: "Unbounce",
        cname_patterns: &["unbouncepages.com"],
        fingerprint: "The page you were looking for doesn't exist",
        risk: RiskLevel::Medium,
        remediation: "Remove CNAME record or recreate the Unbounce page",
    },
    TakeoverSignature {
        service: "Tumblr",
        cname_patterns: &["tumblr.com"],
        fingerprint: "There's nothing here",
        risk: RiskLevel::Medium,
        remediation: "Remove CNAME record or recreate the Tumblr blog",
    },
    TakeoverSignature {
        service: "Ghost",
        cname_patterns: &["ghost.io"],
        fingerprint: "The thing you were looking for is no longer here",
        risk: RiskLevel::Medium,
        remediation: "Remove CNAME record or recreate the Ghost blog",
    },
    TakeoverSignature {
        service: "Pantheon",
        cname_patterns: &["pantheonsite.io"],
        fingerprint: "404 error unknown site",
        risk: RiskLevel::Medium,
        remediation: "Remove CNAME record or reconfigure Pantheon site",
    },
    TakeoverSignature {
        service: "Readme.io",
        cname_patterns: &["readme.io"],
        fingerprint: "Project doesn't exist",
        risk: RiskLevel::Low,
        remediation: "Remove CNAME record or recreate the ReadMe project",
    },
];

// ==================== MAIN SCANNER ====================

pub struct SubdomainScanner {
    censys: Arc<CensysClient>,
    target: String,
    discovered: Arc<tokio::sync::Mutex<HashSet<String>>>,
    results: Arc<tokio::sync::Mutex<Vec<AssetInfo>>>,
}

impl SubdomainScanner {
    pub fn new(token: String, target: String) -> Self {
        Self {
            censys: Arc::new(CensysClient::new(token)),
            target,
            discovered: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            results: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    pub async fn enumerate(&self, threads: usize) -> Result<Vec<AssetInfo>> {
        println!(
            "\n{}",
            "🔍 PHASE 1: Certificate Discovery".bright_blue().bold()
        );
        self.discover_from_certificates().await?;

        println!("\n{}", "🔍 PHASE 2: Host Discovery".bright_blue().bold());
        self.discover_from_hosts().await?;

        println!("\n{}", "🔬 PHASE 3: Deep Analysis".bright_blue().bold());
        self.analyze_all(threads).await?;

        let results = self.results.lock().await.clone();
        Ok(results)
    }

    async fn discover_from_certificates(&self) -> Result<()> {
        // Search for all certificates related to the target domain
        let query = format!("names: {} and tags: trusted", self.target);
        println!("  Query: {}", query.dimmed());

        let certs = self.censys.search_certificates(&query, 100).await?;
        println!("  Found {} trusted certificates", certs.len());

        for cert in certs {
            // Extract all names from certificate
            let mut names = Vec::new();

            if let Some(san) = &cert.parsed.extensions.subject_alt_name {
                names.extend(san.clone());
            }
            if let Some(cert_names) = &cert.parsed.names {
                names.extend(cert_names.clone());
            }

            for name in names {
                if name.ends_with(&self.target) && name != self.target {
                    let clean_name = name.trim_end_matches('.').to_string();
                    if !clean_name.contains('*') {
                        // Skip wildcards
                        self.discovered.lock().await.insert(clean_name);
                    }
                }
            }
        }

        let count = self.discovered.lock().await.len();
        println!("  ✅ Discovered {} unique subdomains", count);
        Ok(())
    }

    async fn discover_from_hosts(&self) -> Result<()> {
        // Search for hosts with this domain in their services
        let query = format!("services.tls.certificate.parsed.names: {}", self.target);
        println!("  Query: {}", query.dimmed());

        let hosts = self.censys.search_hosts(&query, 100).await?;
        println!("  Found {} hosts", hosts.len());

        for host in hosts {
            if let Some(services) = host.services {
                for service in services {
                    if let Some(cert_fp) = service.certificate {
                        // Get certificate details to extract names
                        if let Ok(cert) = self.censys.get_certificate_by_fingerprint(&cert_fp).await
                        {
                            if let Some(names) = cert.parsed.names {
                                for name in names {
                                    if name.ends_with(&self.target) && name != self.target {
                                        self.discovered.lock().await.insert(name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let count = self.discovered.lock().await.len();
        println!("  ✅ Total unique subdomains: {}", count);
        Ok(())
    }

    async fn analyze_all(&self, threads: usize) -> Result<()> {
        let subdomains: Vec<String> = self.discovered.lock().await.iter().cloned().collect();
        println!(
            "  Analyzing {} subdomains with {} threads",
            subdomains.len(),
            threads
        );

        let semaphore = Arc::new(Semaphore::new(threads));
        let mut set = JoinSet::new();

        for subdomain in subdomains {
            let sem = semaphore.clone();
            let censys = self.censys.clone();
            let target = self.target.clone();
            let results = self.results.clone();

            set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let asset = analyze_subdomain(&subdomain, &target, &censys).await;
                results.lock().await.push(asset);
                print!("{}", ".".green());
            });
        }

        while set.join_next().await.is_some() {}
        println!();
        Ok(())
    }
}

async fn analyze_subdomain(subdomain: &str, target: &str, censys: &CensysClient) -> AssetInfo {
    let mut asset = AssetInfo {
        domain: subdomain.to_string(),
        asset_type: "subdomain".to_string(),
        ..Default::default()
    };

    // Get certificate info
    if let Ok(cert_info) = get_certificate_info(subdomain, censys).await {
        asset.certificate = Some(cert_info);
    }

    // Get host/IP info
    if let Ok(hosts) = get_host_info(subdomain, censys).await {
        if let Some(host) = hosts.first() {
            asset.ip = Some(host.ip.clone());

            if let Some(loc) = &host.location {
                asset.location = Some(Location {
                    country: loc.country.clone(),
                    city: loc.city.clone(),
                    latitude: loc.coordinates.as_ref().map(|c| c.latitude),
                    longitude: loc.coordinates.as_ref().map(|c| c.longitude),
                });
            }

            if let Some(as_info) = &host.autonomous_system {
                asset.asn = as_info.asn.map(|n| format!("AS{}", n));
            }

            if let Some(services) = &host.services {
                for service in services {
                    let mut service_info = ServiceInfo {
                        port: service.port,
                        service_name: service.service_name.clone(),
                        transport: service.transport_protocol.clone(),
                        banner: service.banner.clone(),
                        ..Default::default()
                    };

                    if let Some(http) = &service.http {
                        if let Some(resp) = &http.response {
                            let mut http_info = HttpInfo {
                                status_code: resp.status_code,
                                server: resp.server.clone(),
                                title: resp.html_title.clone().or(resp.title.clone()),
                                headers: resp.headers.clone().unwrap_or_default(),
                                ..Default::default()
                            };

                            // Detect technologies
                            if let Some(body) = &resp.body {
                                http_info.technologies =
                                    detect_technologies(&http_info.headers, body);
                            }

                            service_info.http_info = Some(http_info);
                        }
                    }

                    asset.ports.push(service.port);
                    asset.services.push(service_info);
                }
            }
        }
    }

    // Check for takeover risks
    asset.takeover_risk = check_takeover_risk(subdomain, &asset).await;

    // Collect all vulnerabilities
    asset.vulnerabilities = collect_vulnerabilities(&asset);

    asset
}

async fn get_certificate_info(domain: &str, censys: &CensysClient) -> Result<CertificateInfo> {
    let query = format!("names: {}", domain);
    let certs = censys.search_certificates(&query, 1).await?;

    if let Some(cert) = certs.first() {
        let not_after = DateTime::parse_from_rfc3339(&cert.parsed.validity.not_after).unwrap();
        let now = Utc::now();

        // Determine key size
        let key_size = if let Some(rsa) = &cert.parsed.subject_key_info.rsa {
            Some(rsa.length)
        } else if let Some(ec) = &cert.parsed.subject_key_info.ec {
            Some(ec.length)
        } else {
            None
        };

        // Determine validation level
        let validation_level = match cert.parsed.validation_level.as_deref() {
            Some("DV") => "DV".to_string(),
            Some("OV") => "OV".to_string(),
            Some("EV") => "EV".to_string(),
            _ => "Unknown".to_string(),
        };

        Ok(CertificateInfo {
            fingerprint: cert.parsed.fingerprint.clone(),
            subject: cert.parsed.subject.clone(),
            issuer: cert.parsed.issuer.clone(),
            not_before: cert.parsed.validity.not_before.clone(),
            not_after: cert.parsed.validity.not_after.clone(),
            signature_algorithm: cert.parsed.signature_algorithm.name.clone(),
            key_algorithm: cert.parsed.subject_key_info.key_algorithm.name.clone(),
            key_size,
            serial: cert.parsed.serial_number.clone(),
            version: cert.parsed.version,
            subject_alt_names: cert
                .parsed
                .extensions
                .subject_alt_name
                .clone()
                .unwrap_or_default(),
            is_expired: not_after < now,
            expires_soon: !(not_after < now) && not_after < now + chrono::Duration::days(30),
            is_trusted: true, // We filtered by trusted
            validation_level,
        })
    } else {
        bail!("No certificate found")
    }
}

async fn get_host_info(domain: &str, censys: &CensysClient) -> Result<Vec<CensysHost>> {
    let query = format!("services.tls.certificate.parsed.names: {}", domain);
    let hosts = censys.search_hosts(&query, 10).await?;
    Ok(hosts)
}

fn detect_technologies(headers: &HashMap<String, String>, body: &str) -> Vec<String> {
    let mut tech = Vec::new();
    let body_lower = body.to_lowercase();

    // Server header
    if let Some(server) = headers.get("server") {
        tech.push(format!("Server: {}", server));
    }

    // X-Powered-By
    if let Some(powered) = headers.get("x-powered-by") {
        tech.push(format!("X-Powered-By: {}", powered));
    }

    // Common CMS and frameworks
    if body_lower.contains("wp-content") || body_lower.contains("wp-includes") {
        tech.push("WordPress".to_string());
    }
    if body_lower.contains("drupal") {
        tech.push("Drupal".to_string());
    }
    if body_lower.contains("joomla") {
        tech.push("Joomla".to_string());
    }
    if body_lower.contains("laravel") || headers.contains_key("x-laravel") {
        tech.push("Laravel".to_string());
    }
    if body_lower.contains("csrf-token") || headers.contains_key("x-django") {
        tech.push("Django".to_string());
    }
    if headers.contains_key("x-rails") {
        tech.push("Ruby on Rails".to_string());
    }
    if body_lower.contains("react") || body_lower.contains("reactjs") {
        tech.push("React".to_string());
    }
    if body_lower.contains("angular") {
        tech.push("Angular".to_string());
    }
    if body_lower.contains("vue") {
        tech.push("Vue.js".to_string());
    }
    if body_lower.contains("jquery") {
        tech.push("jQuery".to_string());
    }
    if body_lower.contains("bootstrap") {
        tech.push("Bootstrap".to_string());
    }

    tech
}

async fn check_takeover_risk(domain: &str, asset: &AssetInfo) -> Option<TakeoverRisk> {
    // Check if domain has CNAME but no A/AAAA records
    // This is simplified - in reality you'd need to do DNS lookups

    // For now, check if the domain points to a known vulnerable service
    for sig in TAKEOVER_SIGNATURES {
        // Check if any service matches the pattern
        for service in &asset.services {
            if let Some(http) = &service.http_info {
                if let Some(title) = &http.title {
                    if title.contains(sig.fingerprint) {
                        return Some(TakeoverRisk {
                            risk_level: sig.risk.clone(),
                            service_type: sig.service.to_string(),
                            cname_target: Some(service.service_name.clone()),
                            reason: format!(
                                "Service returns '{}' indicating possible takeover",
                                sig.fingerprint
                            ),
                            remediation: sig.remediation.to_string(),
                        });
                    }
                }
            }
        }
    }

    None
}

fn collect_vulnerabilities(asset: &AssetInfo) -> Vec<String> {
    let mut vulns = Vec::new();

    // Certificate issues
    if let Some(cert) = &asset.certificate {
        if cert.is_expired {
            vulns.push("EXPIRED_CERTIFICATE".to_string());
        }
        if cert.expires_soon {
            vulns.push("CERTIFICATE_EXPIRING_SOON".to_string());
        }
        if cert.signature_algorithm.to_lowercase().contains("sha1") {
            vulns.push("WEAK_SIGNATURE_SHA1".to_string());
        }
        if cert.key_algorithm.to_lowercase().contains("rsa") && cert.key_size.unwrap_or(0) < 2048 {
            vulns.push(format!("WEAK_KEY_SIZE_{}", cert.key_size.unwrap_or(0)));
        }
    }

    // Open ports
    if asset.ports.contains(&21) {
        vulns.push("FTP_PORT_OPEN".to_string());
    }
    if asset.ports.contains(&23) {
        vulns.push("TELNET_PORT_OPEN".to_string());
    }
    if asset.ports.contains(&445) {
        vulns.push("SMB_PORT_OPEN".to_string());
    }
    if asset.ports.contains(&3389) {
        vulns.push("RDP_PORT_OPEN".to_string());
    }

    // HTTP issues
    for service in &asset.services {
        if let Some(http) = &service.http_info {
            if let Some(code) = http.status_code {
                if code >= 500 {
                    vulns.push(format!("HTTP_{}_SERVER_ERROR", code));
                }
                if code == 401 || code == 403 {
                    vulns.push(format!("HTTP_{}_ACCESS_CONTROL", code));
                }
            }

            if let Some(server) = &http.server {
                if server.contains("Apache/2.2") || server.contains("IIS/6") {
                    vulns.push(format!("OUTDATED_SERVER_{}", server));
                }
            }
        }
    }

    vulns
}

// ==================== OUTPUT FUNCTIONS ====================

fn print_summary(results: &[AssetInfo]) {
    println!("\n{}", "📊 FINAL REPORT".bright_blue().bold());
    println!("{}", "═".repeat(100).bright_blue());

    // Statistics
    let total = results.len();
    let with_ip = results.iter().filter(|a| a.ip.is_some()).count();
    let with_cert = results.iter().filter(|a| a.certificate.is_some()).count();
    let vulnerable = results
        .iter()
        .filter(|a| !a.vulnerabilities.is_empty())
        .count();
    let takeover_risks = results.iter().filter(|a| a.takeover_risk.is_some()).count();

    println!("\n{}", "📈 Statistics".bright_white().bold());
    println!("  Total Subdomains: {}", total);
    println!(
        "  Resolved to IP: {} ({:.1}%)",
        with_ip,
        (with_ip as f64 / total as f64 * 100.0)
    );
    println!(
        "  Has Certificate: {} ({:.1}%)",
        with_cert,
        (with_cert as f64 / total as f64 * 100.0)
    );
    println!("  Has Vulnerabilities: {}", vulnerable);
    println!("  Takeover Risks: {}", takeover_risks);

    // Takeover risks (most critical)
    let critical: Vec<_> = results.iter()
        .filter(|a| matches!(a.takeover_risk, Some(ref t) if matches!(t.risk_level, RiskLevel::Critical)))
        .collect();

    if !critical.is_empty() {
        println!("\n{}", "🔥 CRITICAL TAKEOVER RISKS".on_red().black().bold());
        for asset in critical {
            if let Some(risk) = &asset.takeover_risk {
                println!("  • {}", asset.domain.bright_white().bold());
                println!("    Service: {}", risk.service_type.yellow());
                println!("    Risk: {:?}", risk.risk_level);
                println!("    Remediation: {}", risk.remediation.dimmed());
            }
        }
    }

    // All assets with details
    println!("\n{}", "📋 DETAILED ASSET LIST".bright_white().bold());
    for asset in results {
        let status = if asset.ip.is_some() {
            "●".green()
        } else {
            "○".red()
        };
        println!("\n  {} {}", status, asset.domain.bright_white().bold());

        if let Some(ip) = &asset.ip {
            println!("    IP: {}", ip.dimmed());

            if !asset.ports.is_empty() {
                println!(
                    "    Ports: {}",
                    asset
                        .ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                        .cyan()
                );
            }

            if let Some(cert) = &asset.certificate {
                let expiry = if cert.is_expired {
                    format!(" (EXPIRED)").red()
                } else if cert.expires_soon {
                    format!(" (EXPIRES SOON)").yellow()
                } else {
                    "".normal()
                };
                println!(
                    "    Certificate: {} until{}{}",
                    cert.issuer.dimmed(),
                    cert.not_after[0..10].dimmed(),
                    expiry
                );
            }

            for service in &asset.services {
                if let Some(http) = &service.http_info {
                    if let Some(code) = http.status_code {
                        let code_str = if code == 200 {
                            code.to_string().green()
                        } else if code < 400 {
                            code.to_string().yellow()
                        } else {
                            code.to_string().red()
                        };
                        println!("    HTTP:{} {}", service.port, code_str);

                        if let Some(title) = &http.title {
                            if title.len() > 50 {
                                println!("      Title: {}...", &title[..47].dimmed());
                            } else {
                                println!("      Title: {}", title.dimmed());
                            }
                        }

                        if !http.technologies.is_empty() {
                            println!("      Tech: {}", http.technologies.join(", ").dimmed());
                        }
                    }
                }
            }
        }

        if !asset.vulnerabilities.is_empty() {
            println!(
                "    {} Vulnerabilities: {}",
                "⚠".yellow(),
                asset.vulnerabilities.join(", ").yellow()
            );
        }
    }
}

async fn save_json_report(path: &str, results: &[AssetInfo]) -> Result<()> {
    let report = serde_json::to_string_pretty(results)?;

    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        create_dir_all(parent).await?;
    }

    let mut file = File::create(path).await?;
    file.write_all(report.as_bytes()).await?;

    println!(
        "\n{} JSON report saved to: {}",
        "✓".green().bold(),
        path.to_string_lossy().bright_cyan()
    );
    Ok(())
}
