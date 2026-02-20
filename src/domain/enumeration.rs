use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use colored::Colorize;
use dns_lookup::lookup_host;
use futures::future::join_all;
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use reqwest::{Client, header::AUTHORIZATION};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet}, path::Path, process::exit, sync::Arc, time::Duration
};
use tokio::{
    fs::{File, create_dir_all},
    io::AsyncWriteExt,
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tracing::warn;
use trust_dns_resolver::{
    AsyncResolver, TokioAsyncResolver,
    error::{ResolveError, ResolveErrorKind},
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
    proto::rr::RecordType,
};

pub type Res = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

#[derive(Debug, Default, Serialize, Clone)]
pub struct SubdomainInfo {
    pub domain: String,
    pub ip: Option<String>,
    pub record_type: String,
    pub issuer: String,
    pub expiry: String,
    pub version: String,
    pub serial: String,
    pub signature: String,
    pub vulnerability: String,
    pub ports: Vec<u16>,
    pub technologies: Vec<String>,
    pub status_code: Option<u16>,
    pub server_header: Option<String>,
    pub title: Option<String>,
}

// ==================== SSLMATE API STRUCTS ====================

#[derive(Debug, Deserialize)]
struct CertSpotterIssuance {
    dns_names: Option<Vec<String>>,
}

// ==================== CENSYS API STRUCTS ====================

#[derive(Debug, Deserialize)]
struct CensysSearchResponse {
    result: CensysResult,
}

#[derive(Debug, Deserialize)]
struct CensysResult {
    hits: Vec<CensysCertificate>,
}

#[derive(Debug, Deserialize)]
struct CensysCertificate {
    #[serde(rename = "parsed")]
    parsed: ParsedCertificate,
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
    #[serde(rename = "extensions")]
    extensions: Extensions,
    #[serde(rename = "serial_number")]
    serial_number: String,
    version: i32,
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
struct Extensions {
    #[serde(rename = "subject_alt_name")]
    subject_alt_name: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CensysHostResponse {
    result: HostResult,
}

#[derive(Debug, Deserialize)]
struct HostResult {
    services: Option<Vec<HostService>>,
}

#[derive(Debug, Deserialize)]
struct HostService {
    port: u16,
    service_name: String,
    transport_protocol: String,
    #[serde(rename = "http")]
    http: Option<HttpInfo>,
}

#[derive(Debug, Deserialize)]
struct HttpInfo {
    response: Option<HttpResponse>,
}

#[derive(Debug, Deserialize)]
struct HttpResponse {
    status_code: Option<u16>,
    headers: Option<HashMap<String, String>>,
    body: Option<String>,
    title: Option<String>,
    server: Option<String>,
}

// ==================== MAIN FUNCTIONS ====================

pub async fn run_domain_lookup(
    target: String,
    output: Option<String>,
    mut threads: usize,
    use_censys: bool,
) -> Result<()> {
    threads = threads.max(1);
    println!("{}", "═".repeat(60).bright_blue());
    println!("🔍 Subdomain Scanner Starting");
    println!("{}", "═".repeat(60).bright_blue());
    println!("Target Domain: {}", target.bright_white().bold());
    println!("Threads: {}", threads);
    println!("Using Censys: {}", if use_censys { "✅ Yes" } else { "❌ No" }.bright_green());
    println!("{}", "─".repeat(60).bold());

    let subdomains = discover_subdomains(&target, use_censys).await?;
    
    if subdomains.is_empty() {
        println!("{} No subdomains found!", "⚠".yellow().bold());
        return Ok(());
    }

    println!("\n{} Found {} unique subdomains", "✓".green().bold(), subdomains.len());
    analyze_subdomains(subdomains, &target, output, threads).await?;

    Ok(())
}

// ==================== SUBDOMAIN DISCOVERY ====================

async fn discover_subdomains(target: &str, use_censys: bool) -> Result<HashSet<String>> {
    let mut all_subdomains = HashSet::new();

    // Try SSLMate first
    match get_subdomains_from_sslmate(target).await {
        Ok(subs) => {
            println!("✅ SSLMate found {} subdomains", subs.len());
            all_subdomains.extend(subs);
        }
        Err(e) => {
            println!("⚠️ SSLMate error: {} - Trying alternatives...", e);
        }
    }

    // Try Censys if enabled
    if use_censys {
        match get_subdomains_from_censys(target).await {
            Ok(subs) => {
                println!("✅ Censys found {} subdomains", subs.len());
                all_subdomains.extend(subs);
            }
            Err(e) => {
                println!("⚠️ Censys error: {}", e);
            }
        }
    }

    // If both failed, use common subdomains as fallback
    if all_subdomains.is_empty() {
        println!("ℹ️ Using common subdomain fallback");
        all_subdomains.extend(get_common_subdomains(target));
    }

    Ok(all_subdomains)
}

async fn get_subdomains_from_sslmate(target: &str) -> Result<HashSet<String>> {
    dotenvy::dotenv().ok();
    let api_key = std::env::var("SSLMATE_API_KEY")
        .context("SSLMATE_API_KEY not found in environment")?;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let encoded = percent_encode(target.as_bytes(), NON_ALPHANUMERIC).to_string();
    let url = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        encoded
    );

    let response = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {}", api_key))
        .send()
        .await?;

    if !response.status().is_success() {
        bail!("SSLMate API error: {}", response.status());
    }

    let issuances: Vec<CertSpotterIssuance> = response.json().await?;
    let mut subdomains = HashSet::new();

    for issuance in issuances {
        if let Some(dns_names) = issuance.dns_names {
            for name in dns_names {
                let clean_name = name.trim_start_matches("*.").to_string();
                if clean_name.ends_with(target) && clean_name != target {
                    subdomains.insert(clean_name);
                }
            }
        }
    }

    Ok(subdomains)
}

async fn get_subdomains_from_censys(target: &str) -> Result<HashSet<String>> {
    dotenvy::dotenv().ok();
    let token = std::env::var("CENSYS_TOKEN")
        .context("CENSYS_TOKEN not found in environment")?;

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    let url = "https://search.censys.io/api/v2/certificates/search";
    
    let query = serde_json::json!({
        "q": format!("names: {} and tags: trusted", target),
        "per_page": 100,
        "fields": ["names"]
    });

    let response = client
        .post(url)
        .bearer_auth(token)
        .json(&query)
        .send()
        .await?;
    dbg!("ddddddddddddddddd");
    if !response.status().is_success() {
        bail!("Censys API error: {}", response.status());
    }

    dbg!(response.text().await?); // Debug raw response for troubleshooting
    exit(0);

    let data: CensysSearchResponse = response.json().await?;
    let mut subdomains = HashSet::new();

    for cert in data.result.hits {
        if let Some(names) = cert.parsed.extensions.subject_alt_name {
            for name in names {
                if name.ends_with(target) && name != target {
                    subdomains.insert(name);
                }
            }
        }
    }

    Ok(subdomains)
}

fn get_common_subdomains(target: &str) -> HashSet<String> {
    let common_subs = vec![
        "www", "mail", "ftp", "api", "dev", "test", "staging", "blog",
        "shop", "admin", "cpanel", "webmail", "ns1", "ns2", "app",
        "docs", "dashboard", "portal", "secure", "vpn", "remote",
        "support", "help", "status", "cdn", "static", "media",
        "images", "assets", "download", "files", "backup",
    ];

    common_subs.into_iter()
        .map(|sub| format!("{}.{}", sub, target))
        .collect()
}

// ==================== SUBDOMAIN ANALYSIS ====================

async fn analyze_subdomains(
    subdomains: HashSet<String>,
    target: &str,
    output: Option<String>,
    threads: usize,
) -> Result<()> {
    let resolver = Arc::new(TokioAsyncResolver::tokio_from_system_conf()?);
    let http_client = Arc::new(Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?);
    
    let semaphore = Arc::new(Semaphore::new(threads));
    let mut set = JoinSet::new();
    let subdomains_vec: Vec<String> = subdomains.into_iter().collect();

    println!("\n{} Analyzing subdomains...", "🔍".bright_blue());
    println!("{}", "─".repeat(40));

    for subdomain in subdomains_vec {
        let resolver = resolver.clone();
        let http_client = http_client.clone();
        let permit = semaphore.clone();
        let target = target.to_string();

        set.spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            analyze_single_subdomain(&subdomain, &target, resolver, http_client).await
        });
    }

    let mut results = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(info) = res {
            print!("{}", ".".bright_green());
            results.push(info);
        }
    }

    println!("\n");
    display_results(&results).await;
    
    if let Some(path) = output {
        save_report(&path, results).await?;
    }

    Ok(())
}

async fn analyze_single_subdomain(
    subdomain: &str,
    target: &str,
    resolver: Arc<TokioAsyncResolver>,
    http_client: Arc<Client>,
) -> SubdomainInfo {
    let mut info = SubdomainInfo {
        domain: subdomain.to_string(),
        ..Default::default()
    };

    // DNS Resolution
    if let Ok(ips) = timeout(Duration::from_secs(3), resolver.lookup_ip(subdomain)).await {
        if let Ok(response) = ips {
            if let Some(ip) = response.iter().next() {
                info.ip = Some(ip.to_string());
                info.record_type = "A".to_string();
            }
        }
    }

    // HTTP/HTTPS Checks if domain resolved
    if info.ip.is_some() {
        for protocol in &["https", "http"] {
            if let Err(e) = check_http_service(subdomain, protocol, &http_client, &mut info).await {
                warn!("HTTP check failed for {}: {}", subdomain, e);
            }
        }

        // Get certificate details from Censys
        if let Err(e) = enrich_with_certificate_data(subdomain, target, &mut info).await {
            warn!("Certificate enrichment failed for {}: {}", subdomain, e);
        }

        // Port scan common ports
        if let Some(ip) = &info.ip {
            if let Ok(ip_addr) = ip.parse() {
                info.ports = scan_common_ports(ip_addr).await;
            }
        }
    } else {
        // Check for takeover if no IP
        let _ = check_takeover(&mut info, &resolver).await;
    }

    info
}

async fn check_http_service(
    domain: &str,
    protocol: &str,
    client: &Client,
    info: &mut SubdomainInfo,
) -> Result<()> {
    let url = format!("{}://{}", protocol, domain);
    
    if let Ok(response) = timeout(Duration::from_secs(3), client.get(&url).send()).await {
        if let Ok(resp) = response {
            info.status_code = Some(resp.status().as_u16());
            
            if let Some(server) = resp.headers().get("server") {
                info.server_header = Some(server.to_str().unwrap_or("").to_string());
            }

            // Clone headers before consuming resp
            let headers = resp.headers().clone();
            
            // Get body text
            if let Ok(body) = resp.text().await {
                if let Some(title) = extract_title(&body) {
                    info.title = Some(title);
                }
                
                // Detect technologies using both headers and body
                info.technologies = detect_technologies(&headers, &body);
            }
        }
    }
    
    Ok(())
}

// Updated detect_technologies to accept headers reference
fn detect_technologies(headers: &reqwest::header::HeaderMap, body: &str) -> Vec<String> {
    let mut tech = Vec::new();

    // Server header
    if let Some(server) = headers.get("server") {
        tech.push(format!("Server: {}", server.to_str().unwrap_or("")));
    }

    // X-Powered-By
    if let Some(powered) = headers.get("x-powered-by") {
        tech.push(format!("X-Powered-By: {}", powered.to_str().unwrap_or("")));
    }

    // WordPress detection
    if body.contains("wp-content") || body.contains("wp-includes") {
        tech.push("WordPress".to_string());
    }

    // PHP detection
    if body.contains(".php") || headers.contains_key("x-powered-by") && 
       headers["x-powered-by"].to_str().unwrap_or("").contains("PHP") {
        tech.push("PHP".to_string());
    }

    // Laravel
    if body.contains("laravel") || headers.contains_key("x-laravel") {
        tech.push("Laravel".to_string());
    }

    // Django
    if headers.contains_key("x-django") || body.contains("csrftoken") {
        tech.push("Django".to_string());
    }

    // Ruby on Rails
    if headers.contains_key("x-rails") {
        tech.push("Ruby on Rails".to_string());
    }

    // Node.js/Express
    if headers.contains_key("x-powered-by") && 
       headers["x-powered-by"].to_str().unwrap_or("").contains("Express") {
        tech.push("Express".to_string());
    }

    tech
}

fn extract_title(html: &str) -> Option<String> {
    html.split("<title>")
        .nth(1)
        .and_then(|s| s.split("</title>").next())
        .map(|s| s.trim().to_string())
}

async fn enrich_with_certificate_data(
    domain: &str,
    target: &str,
    info: &mut SubdomainInfo,
) -> Result<()> {
    dotenvy::dotenv().ok();
    
    let api_id = match std::env::var("CENSYS_API_ID") {
        Ok(id) => id,
        Err(_) => return Ok(()), // Skip if no Censys credentials
    };
    
    let api_secret = match std::env::var("CENSYS_API_SECRET") {
        Ok(secret) => secret,
        Err(_) => return Ok(()),
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let url = "https://search.censys.io/api/v2/certificates/search";
    
    let query = serde_json::json!({
        "q": format!("names: {}", domain),
        "per_page": 1,
        "sort": "parsed.validity.not_after:desc"
    });

    let response = client
        .post(url)
        .basic_auth(api_id, Some(api_secret))
        .json(&query)
        .send()
        .await?;

    if response.status().is_success() {
        let data: CensysSearchResponse = response.json().await?;
        
        if let Some(cert) = data.result.hits.first() {
            info.issuer = cert.parsed.issuer.clone();
            info.expiry = cert.parsed.validity.not_after.clone();
            info.version = cert.parsed.version.to_string();
            info.serial = cert.parsed.serial_number.clone();
            info.signature = cert.parsed.signature_algorithm.name.clone();

            // Check for expiry
            if let Ok(expiry_date) = DateTime::parse_from_rfc3339(&info.expiry) {
                if expiry_date < Utc::now() {
                    info.vulnerability = "EXPIRED_CERTIFICATE".to_string();
                } else if expiry_date < Utc::now() + chrono::Duration::days(30) {
                    info.vulnerability = "EXPIRING_SOON".to_string();
                }
            }

            // Check for weak signature
            if info.signature.to_lowercase().contains("sha1") {
                if info.vulnerability.is_empty() {
                    info.vulnerability = "WEAK_SIG_ALGO_SHA1".to_string();
                } else {
                    info.vulnerability += " | WEAK_SIG_ALGO_SHA1";
                }
            }
        }
    }

    Ok(())
}

async fn scan_common_ports(ip: std::net::IpAddr) -> Vec<u16> {
    let common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9443];
    let mut open = Vec::new();
    
    for &port in &common_ports {
        if let Ok(_) = timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(format!("{}:{}", ip, port))
        ).await {
            open.push(port);
        }
    }
    
    open
}

async fn check_takeover(info: &mut SubdomainInfo, resolver: &Res) -> Result<()> {
    let vulnerable_services = [
        ("github.io", "GitHub Pages"),
        ("herokuapp.com", "Heroku"),
        ("s3.amazonaws.com", "AWS S3"),
        ("azurewebsites.net", "Azure"),
        ("cloudfront.net", "CloudFront"),
        ("unbouncepages.com", "Unbounce"),
        ("surge.sh", "Surge"),
        ("readme.io", "ReadMe"),
        ("ghost.io", "Ghost"),
        ("pantheonsite.io", "Pantheon"),
        ("wordpress.com", "WordPress.com"),
        ("shopify.com", "Shopify"),
        ("tumblr.com", "Tumblr"),
        ("wixsite.com", "Wix"),
        ("squarespace.com", "Squarespace"),
        ("fastly.net", "Fastly"),
    ];

    match resolve_cname(info, resolver).await {
        Ok(cname) => {
            info.record_type = "CNAME".to_string();
            
            for (service_pattern, service_name) in &vulnerable_services {
                if cname.contains(service_pattern) && info.ip.is_none() {
                    info.vulnerability = format!("CRITICAL: Dangling CNAME to {}", service_name);
                    break;
                }
            }
        }
        Err(_) => {
            info.record_type = "NO_RECORDS".to_string();
        }
    }

    Ok(())
}

async fn resolve_cname(info: &mut SubdomainInfo, resolver: &Res) -> Result<String> {
    let lookup = resolver.lookup(&info.domain, RecordType::CNAME).await?;
    for record in lookup.iter() {
        if let Some(cname) = record.as_cname() {
            return Ok(cname.to_string().trim_end_matches('.').to_string());
        }
    }
    bail!("No CNAME records found");
}

// ==================== DISPLAY AND REPORTING ====================

async fn display_results(results: &[SubdomainInfo]) {
    println!("\n{}", "📊 SCAN RESULTS".bright_blue().bold());
    println!("{}", "═".repeat(80).bright_blue());

    let live: Vec<_> = results.iter().filter(|r| r.ip.is_some()).collect();
    let dead: Vec<_> = results.iter().filter(|r| r.ip.is_none()).collect();
    
    println!("Live Subdomains: {}", live.len().to_string().bright_green().bold());
    println!("Dead/Unresolved: {}", dead.len().to_string().bright_yellow().bold());
    println!("{}", "─".repeat(80).dimmed());

    for result in results {
        let status = if result.ip.is_some() { "●".green() } else { "○".red() };
        println!("\n  {} {}", status, result.domain.bright_white().bold());

        if let Some(ip) = &result.ip {
            println!("    IP: {}", ip.dimmed());
            
            if !result.ports.is_empty() {
                println!("    Ports: {}", result.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ").cyan());
            }
            
            if let Some(code) = result.status_code {
                let code_str = if code == 200 { code.to_string().green() } 
                              else if code < 400 { code.to_string().yellow() }
                              else { code.to_string().red() };
                println!("    HTTP: {} {}", code_str, result.server_header.as_deref().unwrap_or("").dimmed());
            }
            
            if let Some(title) = &result.title {
                println!("    Title: {}", title.dimmed());
            }

            if !result.technologies.is_empty() {
                println!("    Tech: {}", result.technologies.join(", ").cyan().dimmed());
            }

            if !result.expiry.is_empty() {
                let expiry_str = if result.vulnerability.contains("EXPIRED") {
                    format!(" (EXPIRED)").red()
                } else if result.vulnerability.contains("EXPIRING") {
                    format!(" (Expiring Soon)").yellow()
                } else {
                    format!("").dimmed()
                };
                println!("    SSL Expiry: {}{}", result.expiry.dimmed(), expiry_str);
            }

            if !result.issuer.is_empty() {
                println!("    Issuer: {}", result.issuer.dimmed());
            }
        } else {
            println!("    Status: {}", "No DNS Resolution".yellow());
            if !result.vulnerability.is_empty() {
                println!("    {} {}", "⚠".yellow(), result.vulnerability.yellow());
            }
        }
    }

    // Summary of vulnerabilities
    let vulnerable: Vec<_> = results.iter().filter(|r| !r.vulnerability.is_empty()).collect();
    if !vulnerable.is_empty() {
        println!("\n{}", "⚠ VULNERABILITIES DETECTED".on_red().black().bold());
        for v in vulnerable {
            println!("  • {}: {}", v.domain.bright_white(), v.vulnerability.yellow());
        }
    }
}

async fn save_report(path: &str, results: Vec<SubdomainInfo>) -> Result<()> {
    let report = serde_json::to_string_pretty(&results)?;
    
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        create_dir_all(parent).await?;
    }

    let mut file = File::create(path).await?;
    file.write_all(report.as_bytes()).await?;
    
    println!("\n{} Report saved to: {}", "✓".green().bold(), path.to_string_lossy().bright_cyan());
    Ok(())
}
