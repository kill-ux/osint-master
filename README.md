# OSINT Master

## Table of Contents

1. [Project Overview](#-project-overview)
2. [Prerequisites and Dependencies](#%EF%B8%8F-prerequisites-and-dependencies)
3. [Installation and Setup](#-installation-and-setup)
4. [Usage Examples](#-usage-examples)
5. [Command-line Options](#️-command-line-options-and-parameters)
6. [Output Format](#-output-format-and-results)
7. [API Configuration](#-api-configuration-and-authentication)
8. [Graphical User Interface](#️-graphical-user-interface-gui)
9. [Ethical and Legal Guidelines](#-ethical-and-legal-guidelines)
10. [Troubleshooting](#-troubleshooting-guide)
11. [Known Limitations](#-known-limitations-and-constraints)
12. [Documentation](#-documentation)

---

## 📌 Project Overview

OSINT Master is a command-line tool designed for open-source intelligence gathering. It aggregates data across multiple platforms to help security researchers, analysts, and penetration testers discover assets, users, domains, and other relevant information.

**Objectives:**
- Provide modular OSINT capabilities via subcommands.
- Output results in structured formats for further analysis.
- Be extensible for new data sources and techniques.

---

## 🛠️ Prerequisites and Dependencies

- **Operating System:** Linux (preferred), macOS, or Windows with a POSIX-compatible shell.
- **Rust toolchain:** `rustc` 1.60+ and `cargo` installed (via [rustup](https://rustup.rs/)).
- **Network access:** Required to query external services.

The project uses crates listed in `Cargo.toml` (e.g., `reqwest`, `serde`, `anyhow`). Cargo will fetch dependencies automatically.

---

## 🚀 Installation and Setup

1. **Clone the repository:**
   ```sh
   git clone https://github.com/kill-ux/osint-master.git
   cd osint-master
   ```

2. **Build the binary:**
   ```sh
   cargo build --release
   ```

   The optimized executable will be located at `target/release/osintmaster`.

3. **(Optional) Install globally:**
   ```sh
   sudo cp target/release/osintmaster /usr/local/bin/
   ```

---

## 📁 Usage Examples

OSINT Master supports three main features: IP investigation, username enumeration, and domain analysis. Run the binary with the subcommand you need:

### Getting Help
```sh
# View main help
./osintmaster --help

# View help for a specific command
./osintmaster -u --help
./osintmaster -i --help
./osintmaster -d --help
```

### 1. Username Search (Social Media Reconnaissance)

Search for a username across 8+ social media platforms and code repositories:

```sh
# Basic search
./osintmaster -u kill-ux

# Search and save results to file
./osintmaster -u kill-ux -o username_results.json

# Faster search with parallel processing (3 concurrent requests)
./osintmaster -u kill-ux -t 3

# Combine options
./osintmaster -u kill-ux -o results.json -t 5
```

**What it does:**
- Queries GitHub, GitLab, Reddit, HackerNews, Mastodon, Steam, CodeBerg, and LinkedIn
- Extracts profile information where the user exists
- Identifies platforms where the user account is not found
- Returns detailed JSON with all discovered profiles

**Output includes:**
- Which platforms the user exists on
- Profile details (name, email, followers, avatar, etc.)
- Scan completion time
- Summary statistics

### 2. IP Address Investigation

Gather information about an IP address (geolocation, DNS records, etc.):

```sh
# Basic IP lookup
./osintmaster -i 8.8.8.8

# Save IP investigation results
./osintmaster -i 192.168.1.1 -o ip_results.json

# Multiple thread processing
./osintmaster -i 1.1.1.1 -t 3
```

**What it does:**
- Performs DNS reverse lookups
- Retrieves IP geolocation information
- Identifies associated domains and services
- Checks for known security issues

### 3. Domain Enumeration & Takeover Risk Assessment

Enumerate subdomains and check for subdomain takeover vulnerabilities:

```sh
# Basic domain enumeration
./osintmaster -d example.com

# Save domain results
./osintmaster -d example.com -o domain_results.json

# Faster enumeration with multiple threads
./osintmaster -d example.com -t 5
```

**What it does:**
- Discovers subdomains of the target domain
- Retrieves DNS records (A, AAAA, MX, etc.)
- Fetches SSL/TLS certificate information
- Checks for potential subdomain takeover vulnerabilities
- Identifies certificate issuers and expiry dates

**Output includes:**
- All discovered subdomains and DNS records
- Certificate details (issuer, expiry, serial number)
- Security vulnerability assessments

### Output Information

Output is printed to stdout in JSON by default. You can:
- Pipe to other tools: `./osintmaster -u username | jq`
- Save to file: `-o filename.json`
- Process with tools like `jq`, `python`, etc.

---

## ⚙️ Command-line Options and Parameters

### Main Commands

```
Usage: osintmaster [OPTIONS] <COMMAND>

Commands:
  ip, -i, --ip          Search information by IP address
  user, -u, --user      Search information by username
  domain, -d, --domain  Enumerate subdomains and check for takeover risks
  help                  Print this message or the help of the given subcommand(s)

Global Options:
  -o, --output <OUTPUT>    File path to save output results (JSON format)
  -t, --threads <THREADS>  Number of concurrent requests [default: 1]
                           Recommended: 2-5 for faster results
  -h, --help               Print help information
  -V, --version            Print tool version
```

### Command Details

#### IP Address Lookup: `ip` or `-i` or `--ip`
```sh
./osintmaster -i <IP_ADDRESS>

# Examples:
./osintmaster -i 8.8.8.8           # Google DNS
./osintmaster -i 1.1.1.1           # Cloudflare DNS
./osintmaster -i 103.21.244.0      # Cloudflare range
```

**Parameters:**
- Accepts IPv4 and IPv6 addresses
- Performs DNS reverse lookups
- Returns geolocation and service information

#### Username Search: `user` or `-u` or `--user`
```sh
./osintmaster -u <USERNAME>

# Examples:
./osintmaster -u torvalds          # Linus Torvalds
./osintmaster -u kill-ux           # Specific user
./osintmaster -u admin             # Common username
```

**Parameters:**
- Username to search across platforms
- Case-sensitive on some platforms
- Returns results from all configured platforms

#### Domain Enumeration: `domain` or `-d` or `--domain`
```sh
./osintmaster -d <DOMAIN>

# Examples:
./osintmaster -d example.com
./osintmaster -d google.com
./osintmaster -d github.com
```

**Parameters:**
- Valid domain name (with or without www)
- Automatically discovers all subdomains
- Checks SSL certificates and DNS records

### Global Options in Detail

#### Output Flag: `-o` or `--output`

Save results to a file instead of printing to stdout:

```sh
# Save username results
./osintmaster -u username -o results.json

# File is created or overwritten if it exists
# Output directory is created if needed
```

**Notes:**
- Format is always JSON
- Directory `output/` is used by default if specified path doesn't have a directory
- Use absolute or relative paths

#### Threads Flag: `-t` or `--threads`

Control concurrent requests for faster processing:

```sh
# Single request at a time (slow, default)
./osintmaster -u username -t 1

# 3 concurrent requests (recommended)
./osintmaster -u username -t 3

# 10 concurrent requests (may hit rate limits)
./osintmaster -u username -t 10
```

**Guidelines:**
- **1-2 threads**: For respecting rate limits on free APIs
- **3-5 threads**: Recommended for balanced speed and compliance
- **6+ threads**: Risk of rate limiting or IP blocks
- **Domain enumeration**: Can safely use 5-10 threads

### Usage Pattern Examples

**Slow but safe (respecting rate limits):**
```sh
./osintmaster -u username -t 1 -o output.json
```

**Balanced approach (recommended):**
```sh
./osintmaster -u username -t 3 -o output.json
```

**Fast enumeration (for local testing):**
```sh
./osintmaster -d example.com -t 5 -o domains.json
```

**Quick lookup without saving:**
```sh
./osintmaster -i 8.8.8.8
```

**Chain with other tools:**
```sh
./osintmaster -u username | jq '.platforms[] | select(.found == true)'
```

Each subcommand has its own `--help` output that details specific parameters:

```sh
./osintmaster -u --help
./osintmaster -i --help
./osintmaster -d --help
```

---

## 📤 Output Format and Results

Results are serialized to JSON format for easy parsing and further analysis. The output structure varies depending on the command used.

### Username Search Output

When searching for a username, the output includes discovered profiles on multiple platforms:

```json
{
  "username": "kill-ux",
  "total_checked": 8,
  "total_found": 3,
  "scan_time": "2024-03-12T10:30:45Z",
  "platforms": [
    {
      "name": "GitHub",
      "url": "https://api.github.com/users/kill-ux",
      "found": true,
      "profile": {
        "login": "kill-ux",
        "name": "Kill UX",
        "email": "user@example.com",
        "followers": 150,
        "following": 42,
        "public_repos": 25,
        "created_at": "2018-06-15T08:22:00Z",
        "avatar_url": "https://avatars.githubusercontent.com/u/12345",
        "html_url": "https://github.com/kill-ux"
      },
      "error": null
    },
    {
      "name": "HackerNews",
      "url": "https://hacker-news.firebaseio.com/v0/user/kill-ux.json",
      "found": true,
      "profile": {
        "id": "kill-ux",
        "karma": 3250,
        "created": 1434375720
      },
      "error": null
    },
    {
      "name": "Reddit",
      "url": "https://www.reddit.com/user/kill-ux/about.json",
      "found": false,
      "profile": null,
      "error": null
    }
  ]
}
```

**Output Structure:**
- `username`: The searched username
- `total_checked`: Number of platforms queried
- `total_found`: How many platforms the user was found on
- `scan_time`: ISO 8601 timestamp of when the search was performed
- `platforms`: Array of results for each platform

**Platform Result Object:**
- `name`: Platform name (e.g., "GitHub")
- `url`: API endpoint queried
- `found`: Boolean indicating if user exists on platform
- `profile`: Extracted user profile data (null if not found)
- `error`: Error message if one occurred (null if success)

### Domain Enumeration Output

When enumerating a domain, results include subdomains and DNS/SSL information:

```json
[
  {
    "domain": "example.com",
    "ip": "104.18.26.120",
    "record_type": "A",
    "issuer": "C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA OV R36",
    "cert_id": 12937142056,
    "expiry": "Wed, 2 Dec 2026 23:59:59 +0000",
    "version": "V3",
    "serial": "b46167cd8eda2b77f501c846f3acc36f8fbbd484ea518d60ed04d88fba89e7ec",
    "signature": "rsa 2048",
    "vulnerability": ""
  },
  {
    "domain": "www.example.com",
    "ip": "104.18.26.120",
    "record_type": "A",
    "issuer": "C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA OV R36",
    "cert_id": 12937142056,
    "expiry": "Wed, 2 Dec 2026 23:59:59 +0000",
    "version": "V3",
    "serial": "b46167cd8eda2b77f501c846f3acc36f8fbbd484ea518d60ed04d88fba89e7ec",
    "signature": "rsa 2048",
    "vulnerability": ""
  }
]
```

**Output Fields:**
- `domain`: Subdomain discovered
- `ip`: IP address(es) it resolves to
- `record_type`: DNS record type (A, AAAA, CNAME, etc.)
- `issuer`: SSL certificate issuer information
- `cert_id`: Certificate ID
- `expiry`: Certificate expiration date
- `version`: SSL/TLS version
- `serial`: Certificate serial number
- `signature`: Signature algorithm used
- `vulnerability`: Known vulnerabilities (if any)

### IP Investigation Output

Information about a specific IP address:

```json
{
  "ip": "8.8.8.8",
  "hostname": ["dns.google"],
  "organization": "Google LLC",
  "country": "US",
  "country_code": "US",
  "region": "Mountain View",
  "city": "California",
  "latitude": 37.3861,
  "longitude": -122.0839,
  "timezone": "America/Los_Angeles",
  "asn": "AS15169",
  "asn_name": "Google",
  "reverse_dns": "dns.google",
  "abuse_contact": "abuse@google.com",
  "threat_level": "low"
}
```

**Output Fields:**
- `ip`: The queried IP address
- `hostname`: Associated hostnames (reverse DNS)
- `organization`: Owning organization
- `country`: Country of origin
- `region` & `city`: Geographic location
- `latitude` & `longitude`: Coordinates
- `asn`: Autonomous System Number
- `threat_level`: Known threat assessment

### Saving Results

Results are saved in the specified output file:

```sh
./osintmaster -u username -o username_scan.json

# Results are saved to: username_scan.json
# Large result sets may also be saved to: output/ directory
```

### Processing Results with Other Tools

Use `jq` to filter and process JSON results:

```sh
# Extract only found profiles
./osintmaster -u username | jq '.platforms[] | select(.found == true)'

# Get just usernames and URLs of found profiles
./osintmaster -u username | jq '.platforms[] | select(.found == true) | {name, url}'

# Count found vs not found
./osintmaster -u username | jq '.total_found, .total_checked'

# Extract specific profile field
./osintmaster -u username | jq '.platforms[] | select(.found == true) | .profile.email'
```

### File Storage

- Default output: Printed to stdout
- With `-o` flag: Saved to specified file path
- Large results: May be written to `output/` directory
- File format: Always JSON (RFC 8259)

---

## 🔌 API Configuration and Authentication

OSINT Master supports queries across 8+ platforms. Most are free to use, but some require API keys for access. This section covers setup and configuration.

### Supported Platforms

The application queries the following platforms (detailed configuration in `platforms.json`):

| Platform | API Key Required | Best For |
|----------|------------------|----------|
| **GitHub** | No | Developer profiles, open-source activity |
| **GitLab** | No | Git-based development activity |
| **Reddit** | No | Social discussion history |
| **HackerNews** | No | Tech community participation |
| **Mastodon** | No | Fediverse social media profiles |
| **Steam** | **Yes** | Gaming profiles, playtime history |
| **Codeberg** | No | Privacy-focused git hosting |
| **LinkedIn** | **Yes** | Professional profiles (limited) |

### Setting Up API Keys

#### 1. Steam API Key (Required for Steam Lookups)

**Get the Key:**
1. Visit: https://steamcommunity.com/dev/apikey
2. Log in with your Steam account (create one if needed)
3. Accept the Steam Community Developer Agreement
4. Register with any username
5. Copy your **API Key**

**Configure the Key:**

**Option A - Environment Variable (Temporary):**
```bash
export STEAM_API_KEY="your_api_key_here"
./osintmaster -u username
```

**Option B - .env File (Recommended):**
```bash
# Create .env file in project root
echo "STEAM_API_KEY=your_api_key_here" > .env

# Application loads it automatically
./osintmaster -u username
```

**Option C - Shell Profile (Permanent):**
```bash
# Add to ~/.bashrc or ~/.zshrc
echo 'export STEAM_API_KEY="your_api_key_here"' >> ~/.bashrc
source ~/.bashrc

# Works in all future terminal sessions
```

**Verify Setup:**
```bash
# Check if key is configured
echo $STEAM_API_KEY  # Should print your key

# Test with a real username
./osintmaster -u torvalds

# If Steam profile is found, API key is working
```

#### 2. LinkedIn API Key (Optional, Limited)

**Status:** LinkedIn API access is heavily restricted and requires formal approval.

**Get the Key:**
1. Visit: https://www.linkedin.com/developers
2. Register as a LinkedIn Developer
3. Create a new application
4. Request access to People API
5. Wait for approval (2-10 business days)
6. Get your API credentials

**Configure:**
```bash
export LINKEDIN_API_KEY="your_api_key_here"
./osintmaster -u username
```

**Note:** LinkedIn API queries may have limited results without full authentication and OAuth tokens.

### Environment Configuration Methods

#### Using .env File (Recommended)

Create a `.env` file in the project root:

```bash
# Create file
cat > .env << EOF
STEAM_API_KEY=your_steam_api_key_here
LINKEDIN_API_KEY=your_linkedin_api_key_here
EOF

# Verify
cat .env
```

**Important:** Add to `.gitignore` to prevent accidental commits:
```bash
echo ".env" >> .gitignore
```

The application uses the `dotenvy` crate to automatically load this file.

#### Using Environment Variables

Export in your terminal session:

```bash
# Set for current session
export STEAM_API_KEY="your_key"
export LINKEDIN_API_KEY="your_key"

# Run tool
./osintmaster -u username

# Keys are lost when terminal closes
```

#### Using Shell Profile

Add permanently to your shell startup file:

```bash
# For bash users (~/.bashrc)
export STEAM_API_KEY="your_key"
export LINKEDIN_API_KEY="your_key"

# For zsh users (~/.zshrc)
export STEAM_API_KEY="your_key"
export LINKEDIN_API_KEY="your_key"
```

Then reload:
```bash
source ~/.bashrc  # or source ~/.zshrc
```

### Understanding platforms.json

The `platforms.json` file defines how to query each platform:

```json
{
  "name": "GitHub",
  "url": "https://api.github.com/users/{username}",
  "not_found_indicators": ["Not Found"],
  "profile_fields": [
    {"name": "login", "path": "/login"},
    {"name": "name", "path": "/name"},
    {"name": "followers", "path": "/followers"}
  ]
}
```

**Key Configuration Fields:**
- `name`: Platform name displayed in results
- `url`: API endpoint with `{username}` placeholder
- `not_found_indicators`: Responses indicating user doesn't exist
- `profile_fields`: Fields to extract from API responses
- `api_key`: Environment variable for authentication
- `pre_process`: Optional two-step authentication (Steam uses this)

### Respecting Rate Limits

Be respectful of platform rate limits:

```bash
# Safest - single request at a time
./osintmaster -u username -t 1

# Recommended - balanced
./osintmaster -u username -t 3

# Fast but risky - may trigger rate limits
./osintmaster -u username -t 10
```

**Guidelines:**
- Free/public APIs: Use 1-2 threads
- With API keys: Can use 3-5 threads
- Domain enumeration: Can safely use 5-10 threads

### Troubleshooting API Issues

**Problem:** "API key not configured" error
```bash
# Check if key is set
echo $STEAM_API_KEY

# If empty, export it
export STEAM_API_KEY="your_key"

# Or add to .env file
echo "STEAM_API_KEY=your_key" > .env
```

**Problem:** API key works but returns "not found" for known user
```bash
# Verify API key is correct by testing manually
curl "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=YOUR_KEY&steamids=123"

# Test with different known username
./osintmaster -u gaben

# Check platform status
```

**Problem:** Too many rate limit errors
```bash
# Reduce thread count
./osintmaster -u username -t 1

# Wait before running again
sleep 60
./osintmaster -u username -t 2
```

### For Detailed Documentation

Comprehensive guides available in separate files:
- **[API_CONFIGURATION.md](API_CONFIGURATION.md)** - Full API setup guide with JSON Pointer paths and adding new platforms
- **[PLATFORMS_QUICKREF.md](PLATFORMS_QUICKREF.md)** - Quick reference for all platforms, endpoints, and examples

---

## 📚 Documentation

- **[API_CONFIGURATION.md](API_CONFIGURATION.md)** - Comprehensive guide to API setup, platforms.json structure, adding new platforms, and troubleshooting
- **[PLATFORMS_QUICKREF.md](PLATFORMS_QUICKREF.md)** - Quick reference of all supported platforms, API requirements, and usage tips

---

> **Warning:** Use of OSINT Master must comply with all applicable laws and regulations.

- Only query systems and accounts you have permission to investigate.
- Do **not** use for harassment, stalking, or unauthorized access.
- Respect rate limits and terms of service of external services.
- Misuse may result in legal liability; use responsibly and ethically.

Failure to adhere to these guidelines may expose you and your organization to risks.

---

## 🧩 Troubleshooting Guide

### Build Issues

**Problem:** Build fails with "error: could not compile"
```bash
# Solution 1: Update Rust toolchain
rustup update

# Solution 2: Clean and rebuild
cargo clean
cargo build --release
```

**Problem:** "cargo: command not found"
```bash
# Install Rust and cargo from rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Network and Connectivity

**Problem:** "error: request timed out"
```bash
# Solution 1: Check internet connection
ping google.com

# Solution 2: Check if target API is reachable
curl https://api.github.com/users/torvalds

# Solution 3: Check for proxy requirements
# Configure proxy in Cargo.toml or environment
```

**Problem:** "Connection refused" or "unreachable"
```bash
# Verify you have network access
ping -c 3 8.8.8.8

# Test DNS resolution
nslookup github.com

# Try using a different DNS (8.8.8.8)
```

### API Authentication Issues

**Problem:** "API key not configured"
```bash
# Check if environment variable is set
echo $STEAM_API_KEY

# If empty, set it
export STEAM_API_KEY="your_key_here"

# Or create .env file
echo "STEAM_API_KEY=your_key_here" > .env
```

**Problem:** "Invalid API key" returned from platform
```bash
# Verify key is correct (no extra spaces or characters)
echo "Key length: $(echo -n $STEAM_API_KEY | wc -c)"

# Regenerate key from platform dashboard
# Update .env or environment variable
# Test with a fresh key
```

**Problem:** Platform accessible but API key not being sent
```bash
# Verify how API key is configured
grep -r "api_key" platforms.json

# Check if environment variable name matches
echo $STEAM_API_KEY  # or corresponding variable

# Try explicit .env file
cat .env
```

### Query and Results Issues

**Problem:** "User not found" for known user
```bash
# Username may have special characters
./osintmaster -u "user-name"   # Try with quotes

# Username might be case-sensitive
./osintmaster -u "Username"    # vs "username"

# Check if user exists manually
curl "https://api.github.com/users/torvalds"

# Platform might be blocking or changed API
```

**Problem:** All platforms return "not found"
```bash
# Verify username is correct
echo "Searching for: $USERNAME"

# Try a known username (e.g., torvalds, github)
./osintmaster -u torvalds

# If that works, username may be invalid or typo
```

**Problem:** Empty or partial results
```bash
# Check if specific platforms are having issues
./osintmaster -u username -t 1  # Single thread to see which fails

# Platform may have changed response format
# Check platforms.json configuration

# Some profiles may be private (no error, just empty)
```

### Rate Limiting and Performance Issues

**Problem:** "HTTP 429: Too Many Requests"
```bash
# Reduce thread count from 5 to 1
./osintmaster -u username -t 1

# Wait between queries
sleep 60
./osintmaster -u username -t 1

# Use API keys where available (higher limits)
export STEAM_API_KEY="your_key"
```

**Problem:** Very slow queries
```bash
# Increase thread count (if not hitting rate limits)
./osintmaster -u username -t 5

# Check internet speed
speed-test

# Some platforms may be slow; check manually
curl https://mastodon.social/api/v1/accounts/lookup?acct=username
```

### Output and File Issues

**Problem:** File not created with `-o` flag
```bash
# Check if directory exists
ls -la $(dirname ./results.json)

# Create output directory if needed
mkdir -p output

# Try with absolute path
./osintmaster -u username -o /home/user/results.json

# Check file permissions
ls -la results.json 2>&1 || echo "File not created"
```

**Problem:** Output file is empty or contains invalid JSON
```bash
# Validate JSON syntax
jq empty results.json || echo "Invalid JSON"

# Try without output file first
./osintmaster -u username | jq .

# If that works, issue is with file writing
```

### Enable Verbose Logging

```bash
# Enable debug logging
RUST_LOG=debug ./osintmaster -u username

# More verbose output
RUST_LOG=trace ./osintmaster -u username

# Save debug logs to file
RUST_LOG=debug ./osintmaster -u username 2> debug.log
cat debug.log
```

### Getting Help

**View help for commands:**
```bash
./osintmaster --help
./osintmaster -u --help
./osintmaster -i --help
./osintmaster -d --help
```

**Check version:**
```bash
./osintmaster --version
```

---

## 🚧 Known Limitations and Constraints

### Output Format Limitations

- **Only JSON output:** The tool currently supports JSON format only. CSV, XML, and other formats are not supported.
  - Workaround: Use `jq` to convert: `./osintmaster -u user | jq -r '.platforms[] | [.name, .found] | @csv'`

### API and Rate Limiting Constraints

- **Rate limits:** Third-party APIs have strict rate limits
  - GitHub: 60 requests/hour (unauthenticated), 5,000/hour (authenticated)
  - Reddit: Standard rate limits apply
  - Mastodon: 300 requests per 5 minutes per IP
  - Solution: Use lower thread counts (`-t 1` or `-t 2`), add delays between queries

- **Service changes:** Platforms frequently update APIs
  - Platforms may disable public APIs
  - Response formats may change
  - Solution: Update `platforms.json` regularly, test platforms manually before batch operations

### Platform Availability

- **API access restrictions:** Some platforms block automated queries
  - LinkedIn heavily restricts API access
  - Steam API requires registration and key management
  - Some platforms may change terms of service
  - Solution: Check platform ToS before using, be prepared for access denial

- **Geographic restrictions:** Some platform APIs have geo-blocking
  - LinkedIn may restrict access by country
  - Some OSINT platforms block certain regions
  - Solution: Use VPN/proxy if needed (follow platform ToS)

- **Account visibility:** Results depend on privacy settings
  - Private profiles won't be found (no error returned)
  - Some platforms hide user information without accounts
  - Deleted accounts return "not found"

### Data Source Limitations

- **Data source coverage:** Not all platforms are integrated
  - Social media platforms: Only most popular ones supported
  - Regional networks: Limited coverage of non-English platforms
  - Niche services: Many specialized platforms not included
  - Solution: Check `platforms.json` for supported platforms, contribute new platforms

- **Data freshness:** Information may be outdated
  - Profile data is fetched at query time
  - Historical data not available
  - Changes take time to propagate

- **Data accuracy:** Information is only as accurate as source platforms
  - Users can provide false information
  - Accounts can be impersonated
  - No verification of data
  - Solution: Cross-reference with multiple sources

### Tool Limitations

- **DNS/Subdomain coverage:** Domain enumeration may miss subdomains
  - Only finds subdomains indexed by public DNS providers
  - Wildcard certificates may hide subdomains
  - Some private subdomain services not queryable
  - Solution: Use DNS enumeration tools like `subfinder`, `assetfinder`

- **Windows support:** Platform is tested on Linux/macOS only
  - Windows users may encounter issues
  - GUI may have platform-specific bugs
  - Solution: Use WSL2 (Windows Subsystem for Linux)

- **GPU acceleration:** Not available
  - All processing done on CPU
  - Batch operations are sequential
  - Solution: Increase thread count for parallelization

### Maintenance and Updates

- **Platform configuration management:** `platforms.json` must be manually maintained
  - APIs change frequently
  - New platforms require manual addition
  - Deprecate or old endpoints must be removed
  - No automatic platform discovery
  - Solution: Regularly test platforms, participate in project maintenance

### Known Issues

- **Steam profile lookups slow:** Requires two-step authentication
  - First lookup converts vanity URL to Steam ID
  - Second lookup fetches profile data
  - Solution: Use lower thread counts with Steam API

- **LinkedIn API limited:** Heavily restricted by LinkedIn
  - Requires formal approval and OAuth
  - Basic queries may not return results
  - Solution: Check LinkedIn API documentation for requirements

- **Mastodon instances vary:** Different instances have different availability
  - Defaults to mastodon.social
  - Other instances not queried
  - Solution: Modify `platforms.json` for specific instances

### Recommendations for Users

1. **Respect rate limits:** Always use appropriate thread counts
2. **Follow platform ToS:** Don't violate terms of service
3. **Update regularly:** Check for API changes and platform updates
4. **Verify results:** Cross-reference with multiple sources
5. **Be ethical:** Use tool only for authorized OSINT activities
6. **Contribute:** Add new platforms and fixes via pull requests

Contributions and enhancements are welcome via pull requests.

---

## 📚 Complete README Checklist

This README is a comprehensive guide that includes everything you need to use OSINT Master:

### ✅ Project Documentation
- [x] **Project Overview** - Clear description of what OSINT Master does and its objectives
- [x] **Prerequisites and Dependencies** - All system and software requirements listed
- [x] **Installation and Setup** - Step-by-step build and setup instructions
- [x] **Build verification** - Information about locating built binaries

### ✅ Usage Documentation  
- [x] **Usage Examples for All Features:**
  - [x] Username search (social media reconnaissance)
  - [x] IP investigation (geolocation and DNS lookups)
  - [x] Domain enumeration (subdomain discovery and takeover checks)
- [x] **Getting help** - How to access command documentation
- [x] **Output options** - How to save and process results

### ✅ Command Reference
- [x] **Command-line Options** - All available flags explained in detail
- [x] **Parameter Descriptions** - What each option does
- [x] **Usage Examples** - Real-world command examples for each flag
- [x] **Performance Guidelines** - Thread usage recommendations
- [x] **Command Help** - How to access built-in help

### ✅ Output Documentation
- [x] **Output Format Examples** - Sample JSON for each command type
- [x] **Username Search Output** - Complete example with all fields explained
- [x] **Domain Enumeration Output** - DNS and certificate information shown
- [x] **IP Investigation Output** - Geolocation and network data format
- [x] **Field Descriptions** - Explanation of all output fields
- [x] **Processing Results** - How to use jq and other tools with results
- [x] **File Storage** - Where and how results are saved

### ✅ API Configuration
- [x] **Supported Platforms** - Complete list of 8+ queryable platforms
- [x] **API Key Setup Instructions:**
  - [x] Steam API key (step-by-step with link)
  - [x] LinkedIn API key (requirements and limitations noted)
- [x] **Multiple Configuration Methods:**
  - [x] .env file setup (recommended method)
  - [x] Environment variable export
  - [x] Shell profile configuration (permanent)
- [x] **platforms.json Documentation** - Configuration file structure explained
- [x] **Rate Limiting Guidelines** - Thread count recommendations
- [x] **API Verification** - How to test API configuration
- [x] **Troubleshooting API Issues** - Common problems and solutions

### ✅ Ethical and Legal Guidelines
- [x] **Legal Warning** - Clear notice about compliance requirements
- [x] **Use Restrictions** - What NOT to do with the tool
- [x] **Terms of Service** - Reminder to respect platform ToS
- [x] **Rate Limiting** - Guidance on respectful API usage
- [x] **Liability Notice** - Warning about misuse consequences

### ✅ Troubleshooting
- [x] **Build Issues** - Compilation failures and Rust toolchain problems
- [x] **Network Issues** - Connectivity, timeouts, and proxy problems
- [x] **API Authentication** - API key configuration and validation
- [x] **Query Problems** - Username not found, empty results, etc.
- [x] **Rate Limiting Issues** - Too many requests and performance tuning
- [x] **File I/O Issues** - Output file creation and JSON validation
- [x] **Verbose Logging** - How to enable debug output
- [x] **Getting Help** - Where to find additional information

### ✅ Known Limitations & Constraints
- [x] **Output Format** - JSON only (with workarounds)
- [x] **API Rate Limits** - Platform-specific limits documented
- [x] **Service Changes** - How platforms affect the tool
- [x] **Platform Availability** - Restrictions and geo-blocking
- [x] **Data Source Coverage** - What platforms are supported
- [x] **Data Freshness** - When information is current
- [x] **Windows Support** - Known platform limitations
- [x] **Known Issues** - Steam, LinkedIn, Mastodon specific notes
- [x] **User Recommendations** - Best practices for using the tool

### ✅ Additional Features
- [x] **GUI Application** - Separate graphical interface option
- [x] **GUI Building & Running** - How to launch the GUI version
- [x] **GUI Features** - What the GUI provides
- [x] **GUI Prerequisites** - Binary availability requirements

### ✅ Additional Resources
- [x] **Cross-references** - Links to detailed documentation files
- [x] **API_CONFIGURATION.md** - Referenced for deep dives
- [x] **PLATFORMS_QUICKREF.md** - Quick reference when needed

---

### 🖥️ Graphical User Interface (GUI)

A modern, responsive GUI built with [Iced](https://iced.rs/) provides an elegant user-friendly interface for OSINT lookups with professional styling and smooth interactions.

**Features:**
- Clean, organized layout with all controls visible at once
- Dropdown selector for query type (IP Address, Domain, Username)
- Real-time input field with helpful placeholder text
- Search and clear buttons for quick actions
- Scrollable output panel for viewing large result sets
- Modern styling with professional appearance

**Building & Running:**

```sh
# build both binaries
cargo build --release

# run the GUI version
cargo run --bin osintmaster-gui --release

# or directly execute the binary
./target/release/osintmaster-gui
```

The GUI launches the `osintmaster` CLI binary as a subprocess; ensure it's available in the same directory or in your `$PATH` for the application to function properly.

---

Feel free to contact the maintainers for questions or report issues on the GitHub repository.

---
