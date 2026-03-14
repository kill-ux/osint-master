# API Configuration and Platform Usage Guide

This document explains how to configure and use the `platforms.json` file in OSINT Master for querying various social media and service platforms.

---

## Table of Contents

1. [Overview](#overview)
2. [platforms.json Structure](#platformsjson-structure)
3. [API Key Configuration](#api-key-configuration)
4. [Platform Configuration Reference](#platform-configuration-reference)
5. [Adding New Platforms](#adding-new-platforms)
6. [Usage Examples](#usage-examples)
7. [Troubleshooting](#troubleshooting)

---

## Overview

The `platforms.json` file is the core configuration file that defines how OSINT Master queries external services. It contains information about:

- API endpoints for various platforms
- How to extract relevant user profile data
- Detection patterns for non-existent accounts
- API key requirements
- Special handling for multi-step authentication

The application loads this file at runtime and uses it to scan a username across all configured platforms simultaneously.

---

## platforms.json Structure

The file is a JSON array of platform objects, each with the following schema:

```json
{
  "name": "Platform Name",
  "url": "https://api.platform.com/user/{username}",
  "pre_url": "Optional URL for initial token/ID lookup",
  "pre_process": {
    "url": "Preprocessing URL with {username} and {key} placeholders",
    "response_path": "/path/to/extract/from/response",
    "not_found_indicators": ["Error message if user not found"]
  },
  "api_key": "ENVIRONMENT_VARIABLE_NAME",
  "not_found_indicators": ["Error response patterns"],
  "profile_fields": [
    {
      "name": "field_display_name",
      "path": "/json/pointer/path"
    }
  ],
  "html_extractors": [
    {
      "name": "field_name",
      "pattern": "regex_pattern",
      "group": 1
    }
  ]
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Human-readable platform name (e.g., "GitHub") |
| `url` | String | Yes | API endpoint with `{username}` placeholder for substitution |
| `pre_url` | String | No | URL for optional pre-processing step (e.g., converting vanity URLs to IDs) |
| `pre_process` | Object | No | Configuration for two-step authentication flow |
| `api_key` | String | No | Environment variable name containing the API key |
| `not_found_indicators` | Array | Yes | Strings/patterns indicating the user doesn't exist on the platform |
| `profile_fields` | Array | No | Specific fields to extract from successful API responses |
| `html_extractors` | Array | No | Regular expression patterns for extracting data from HTML responses |

---

## API Key Configuration

### Setting up API Keys

Some platforms require API keys for authentication. Configure them using environment variables:

#### Option 1: Export in Terminal

```bash
export STEAM_API_KEY="your_api_key_here"
export LINKEDIN_API_KEY="your_api_key_here"
```

Then run OSINT Master in the same terminal session:

```bash
./osintmaster -u username
```

#### Option 2: Create a .env File

Create a `.env` file in the project root:

```env
STEAM_API_KEY=your_steam_api_key
LINKEDIN_API_KEY=your_linkedin_api_key
```

The application uses `dotenvy` crate to automatically load this file.

#### Option 3: Permanent System Setup

Add to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
export STEAM_API_KEY="your_steam_api_key"
export LINKEDIN_API_KEY="your_linkedin_api_key"
```

### Obtaining API Keys

**GitHub**: https://github.com/settings/tokens
- No key required for basic user lookup
- Optional for increased rate limits

**Steam**: https://steamcommunity.com/dev/apikey
- Required for Steam profile lookups
- Free to register with a Steam account

**LinkedIn**: https://www.linkedin.com/developers
- Requires developer account and application approval

**Other Platforms**: Check individual platform documentation

---

## Platform Configuration Reference

### Simple Platforms (No Special Processing)

These platforms accept a direct HTTP GET request with the username in the URL.

#### GitHub Example

```json
{
  "name": "GitHub",
  "url": "https://api.github.com/users/{username}",
  "not_found_indicators": ["Not Found"],
  "profile_fields": [
    {"name": "login", "path": "/login"},
    {"name": "name", "path": "/name"},
    {"name": "email", "path": "/email"},
    {"name": "followers", "path": "/followers"},
    {"name": "avatar_url", "path": "/avatar_url"},
    {"name": "html_url", "path": "/html_url"}
  ]
}
```

**How it works:**
1. Application replaces `{username}` with the search term
2. Makes HTTP GET request to: `https://api.github.com/users/kill-ux`
3. If successful (HTTP 200), extracts fields listed in `profile_fields`
4. If response matches `not_found_indicators`, marks as not found

---

### Platforms with Multi-Step Authentication

Some platforms require a two-step process:
1. **First request** (pre_url): Convert vanity username to ID
2. **Second request** (url): Look up profile using the ID

#### Steam Example

```json
{
  "name": "Steam",
  "url": "http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key={key}&steamids={id}",
  "pre_process": {
    "url": "https://api.steampowered.com/ISteamUser/ResolveVanityURL/v1/?key={key}&vanityurl={username}",
    "response_path": "/response/steamid",
    "not_found_indicators": ["The specified profile could not be found"]
  },
  "api_key": "STEAM_API_KEY",
  "not_found_indicators": ["The specified profile could not be found"],
  "profile_fields": [
    {"name": "steamid", "path": "/response/players/0/steamid"},
    {"name": "personaname", "path": "/response/players/0/personaname"},
    {"name": "avatar", "path": "/response/players/0/avatarfull"},
    {"name": "timecreated", "path": "/response/players/0/timecreated"}
  ]
}
```

**How it works:**
1. First, requests the `pre_process.url` with the username
2. Extracts the steam ID from the response using `response_path`: `/response/steamid`
3. Uses the steam ID to replace `{id}` in the main `url`
4. Makes the actual profile lookup request
5. Extracts fields from the response

**Placeholders:**
- `{username}`: The search term
- `{key}`: API key from environment variable
- `{id}`: Value extracted from pre_process response

---

### JSON Pointer Paths

The `path` field uses JSON Pointer notation (RFC 6901) to extract nested values.

Examples:

```
"/name"                    → json.name
"/data/name"              → json.data.name
"/response/players/0/id"  → json.response.players[0].id
```

**Navigating JSON Responses:**

For a response like:
```json
{
  "data": {
    "user": {
      "profile": {
        "name": "John Doe",
        "email": "john@example.com"
      }
    }
  }
}
```

Use paths like:
- `"/data/user/profile/name"` → "John Doe"
- `"/data/user/profile/email"` → "john@example.com"

---

## Adding New Platforms

### Step 1: Research the Platform API

1. Find the API documentation
2. Determine the endpoint structure
3. Identify required authentication
4. Test with curl or Postman

Example test:
```bash
curl "https://api.example.com/users/testuser"
```

### Step 2: Determine the Response Structure

Save a sample response and analyze the structure:

```bash
curl "https://api.example.com/users/testuser" | jq .
```

Identify:
- The JSON paths to relevant fields
- How the API indicates "user not found"
- Whether a multi-step process is needed

### Step 3: Add to platforms.json

```json
{
  "name": "Example Platform",
  "url": "https://api.example.com/users/{username}",
  "not_found_indicators": ["User not found", "404"],
  "profile_fields": [
    {"name": "username", "path": "/username"},
    {"name": "email", "path": "/email"},
    {"name": "followers", "path": "/stats/followers"}
  ]
}
```

### Step 4: Test the Configuration

```bash
./osintmaster -u testuser
```

Check the output to verify:
- The platform is loaded and checked
- Fields are correctly extracted
- Error handling works as expected

---

## Usage Examples

### Basic Username Search

```bash
./osintmaster -u kill-ux
```

The application will:
1. Load all platforms from `platforms.json`
2. Query each platform for the username
3. Display results for found accounts
4. Show which platforms the user isn't on

### Save Results to File

```bash
./osintmaster -u kill-ux -o results.json
```

Output format:
```json
{
  "username": "kill-ux",
  "total_checked": 8,
  "total_found": 3,
  "platforms": [
    {
      "url": "https://api.github.com/users/kill-ux",
      "name": "GitHub",
      "found": true,
      "profile": {
        "login": "kill-ux",
        "name": "Kill UX",
        "email": "user@example.com",
        "followers": 42
      },
      "error": null
    }
  ],
  "scan_time": "2024-03-12T10:30:45Z"
}
```

### Parallel Processing with Multiple Threads

```bash
./osintmaster -u kill-ux -t 5
```

The `-t` flag controls concurrency (default: 1).
- More threads = faster scans but higher API usage
- Recommended: 3-5 threads to avoid rate limiting

---

## Troubleshooting

### Platform Not Loading

**Error:** `Failed to load platforms.json`

**Solution:**
- Verify `platforms.json` exists in the current directory
- Check JSON syntax: `cat platforms.json | jq .`
- Ensure proper file permissions: `chmod 644 platforms.json`

### API Key Not Recognized

**Error:** `API key missing for platform`

**Solution:**
```bash
# Verify environment variable is set
echo $STEAM_API_KEY

# If not set, export it
export STEAM_API_KEY="your_key_here"

# Or create .env file
echo "STEAM_API_KEY=your_key_here" > .env
```

### User Found But Profile Empty

**Cause:** JSON Pointer paths may be incorrect

**Solution:**
1. Manual test: `curl "https://platform.com/api/user/testuser" | jq .`
2. Verify the paths in `profile_fields` match the response structure
3. Update paths as needed

### Rate Limiting Issues

**Error:** HTTP 429 or "Too many requests"

**Solution:**
- Reduce thread count: `-t 1`
- Add delays in `platforms.json` processing (requires code changes)
- Check platform rate limit documentation
- Use API keys to increase rate limits (where available)

### Mixed Results (Found/Not Found Inconsistent)

**Cause:** `not_found_indicators` not matching actual error responses

**Solution:**
1. Test the endpoint manually
2. Capture the actual error response
3. Add new indicators to `not_found_indicators`
4. Example: `"not_found_indicators": ["Not Found", "404", "User not found"]`

---

## Best Practices

1. **API Key Safety**
   - Never commit API keys to version control
   - Use `.env` file and add it to `.gitignore`
   - Rotate keys regularly

2. **Rate Limiting**
   - Be respectful of platform rate limits
   - Use appropriate thread counts
   - Check platform ToS before automation

3. **Maintenance**
   - Test platforms regularly (APIs change)
   - Update inactive platforms
   - Remove broken endpoints

4. **Profile Field Selection**
   - Only extract necessary fields
   - Reduces response parsing overhead
   - Improves clarity of results

5. **Error Handling**
   - Provide comprehensive `not_found_indicators`
   - Log errors for debugging
   - Test with both existing and non-existing users

---

## Legal & Ethical Considerations

⚠️ **Important:** Ensure compliance with:

- Platform Terms of Service
- Rate limiting requirements
- Local laws and regulations
- GDPR, CCPA, and other privacy laws
- Intended use of gathered information

Misuse may result in:
- IP bans from platforms
- Legal action
- Account suspension

Use OSINT Master responsibly and ethically.

---

## Additional Resources

- [JSON Pointer (RFC 6901)](https://tools.ietf.org/html/rfc6901)
- [Reqwest HTTP Client](https://github.com/seanmonstar/reqwest)
- [Serde JSON](https://docs.serde.rs/serde_json/)

---

For questions or contributions, please refer to the main README.md or contact the project maintainers.
