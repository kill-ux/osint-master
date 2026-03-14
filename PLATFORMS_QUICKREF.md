# Platforms Quick Reference

This file provides a quick overview of all configured platforms in OSINT Master. For detailed configuration and setup instructions, see [API_CONFIGURATION.md](API_CONFIGURATION.md).

## Platforms Summary

| Platform | API Key Required | Status | Fields Extracted |
|----------|------------------|--------|-------------------|
| GitHub | No | ✅ Active | login, name, email, followers, avatar_url, bio, created_at |
| GitLab | No | ✅ Active | name, username, email, followers, avatar_url, created_at |
| Reddit | No | ✅ Active | username, total_karma, link_karma, followers, created_utc |
| HackerNews | No | ✅ Active | id, karma, created |
| Mastodon | No | ✅ Active | display_name, username, followers, following, avatar_url |
| Steam | **Yes** | ✅ Active | steamid, personaname, avatar, timecreated, loccountrycode |
| Codeberg | No | ✅ Active | id, login, full_name, followers_count, created_at |
| LinkedIn | **Yes** | ⚠️ Limited | firstName, lastName, headline, location, vanityName |

---

## API Key Requirements

### Steam (REQUIRED for Steam queries)

**How to get:**
1. Navigate to https://steamcommunity.com/dev/apikey
2. Sign in with your Steam account (create one if needed)
3. Register as a developer with any valid username
4. Copy your API key

**Set the key:**
```bash
export STEAM_API_KEY="your_key_here"
```

### LinkedIn (REQUIRED for LinkedIn queries)

**How to get:**
1. Register at https://www.linkedin.com/developers
2. Create a new application
3. Request access to the People API
4. Wait for approval (may take several days)
5. Copy your API credentials

**Set the key:**
```bash
export LINKEDIN_API_KEY="your_key_here"
```

---

## Platform Details

### ✅ Free Platforms (No Authentication Required)

#### GitHub
- **Endpoint:** `https://api.github.com/users/{username}`
- **Rate Limit:** 60 requests/hour (unauthenticated), 5000/hour (authenticated)
- **Best For:** Developers, open-source contributors
- **Example:** `./osintmaster -u torvalds`

#### GitLab
- **Endpoint:** `https://gitlab.com/api/v4/users?username={username}`
- **Rate Limit:** Default rate limits apply
- **Best For:** Developers using GitLab instances
- **Example:** `./osintmaster -u torvalds`

#### Reddit
- **Endpoint:** `https://www.reddit.com/user/{username}/about.json`
- **Rate Limit:** Follows standard Reddit rate limiting
- **Best For:** Social discussion participants
- **Example:** `./osintmaster -u spez`

#### HackerNews
- **Endpoint:** `https://hacker-news.firebaseio.com/v0/user/{username}.json`
- **Rate Limit:** No explicit limits on user queries
- **Best For:** Tech-savvy users and developers
- **Example:** `./osintmaster -u dang`

#### Mastodon
- **Endpoint:** `https://mastodon.social/api/v1/accounts/lookup?acct={username}`
- **Rate Limit:** 300 requests per 5 minutes per IP
- **Best For:** Fediverse social media users
- **Example:** `./osintmaster -u mastodonpy_dev`

#### Codeberg
- **Endpoint:** `https://codeberg.org/api/v1/users/{username}`
- **Rate Limit:** No strict limits for API
- **Best For:** Users of privacy-focused Git hosting
- **Example:** `./osintmaster -u gitea`

---

### 🔑 Authenticated Platforms

#### Steam
- **Endpoint:** Requires two-step authentication
  1. Convert vanity URL to Steam ID
  2. Lookup profile by Steam ID
- **API Key Env Variable:** `STEAM_API_KEY`
- **Rate Limit:** Based on your API key quota
- **Best For:** Gaming profiles
- **Getting Started:**
  ```bash
  export STEAM_API_KEY="your_key"
  ./osintmaster -u username
  ```

#### LinkedIn
- **Endpoint:** `https://api.linkedin.com/v2/people/(id:{id})`
- **API Key Env Variable:** `LINKEDIN_API_KEY`
- **Rate Limit:** API quota dependent
- **Status:** Requires approval from LinkedIn
- **Best For:** Professional profiles
- **Note:** LinkedIn API access is limited; approval required

---

## Configuration Patterns

### Simple Lookup (Single API Call)

Most platforms use this pattern:
```json
{
  "name": "Platform",
  "url": "https://api.platform.com/user/{username}",
  "not_found_indicators": ["Not Found"],
  "profile_fields": [...]
}
```

### Two-Step Lookup (Pre-processing)

Platforms like Steam that need ID conversion:
```json
{
  "name": "Steam",
  "url": "https://...?steamids={id}",
  "pre_process": {
    "url": "https://...?vanityurl={username}&key={key}",
    "response_path": "/response/steamid"
  },
  "api_key": "STEAM_API_KEY"
}
```

---

## Common Response Patterns

### User Found (HTTP 200 + Valid JSON)
```json
{
  "login": "username",
  "name": "Real Name",
  "followers": 42,
  "avatar_url": "https://..."
}
```

### User Not Found (HTTP 404)
- Platform returns 404 status
- Listed in `not_found_indicators`

### Empty Response
- Empty JSON object `{}`
- Empty JSON array `[]`
- `null` value

---

## Tips for Effective Searches

### Search Parameters
```bash
# Single username across all platforms
./osintmaster -u username

# Save to file for analysis
./osintmaster -u username -o results.json

# Increase speed with more threads (1-5 recommended)
./osintmaster -u username -t 3

# Combine flags
./osintmaster -u username -o results.json -t 3
```

### Interpreting Results

The output shows:
- ✅ **Found**: User exists on platform
- ❌ **Not Found**: User doesn't exist or profile is private
- ⚠️ **Error**: API error or connectivity issue

Example output snippet:
```
🔍 USERNAME SCAN RESULTS: username
═════════════════════════════════════
Found on 4/8 platforms
─────────────────────────────────────

YES ⣿⣿ GitHub
     URL: https://api.github.com/users/username
     login: username
     name: Real Name
     followers: 150
     avatar_url: https://avatars.githubusercontent.com/u/12345

NO  ⣿⣿ LinkedIn
     URL: https://api.linkedin.com/v2/people/(id:username)
     ⚠️ Error: API key not configured
```

---

## Troubleshooting Quick Guide

| Issue | Solution |
|-------|----------|
| "Platform not found" error | Verify `platforms.json` exists in current directory |
| API key not recognized | Check env var: `echo $STEAM_API_KEY` |
| All platforms return "not found" | Verify the username is correct and public |
| High number of errors | Check internet connection and platform status |
| Slow performance | Reduce thread count or check rate limits |

---

## Adding New Platforms

To add a new platform to `platforms.json`:

1. **Research the API**
   - Find the endpoint structure
   - Check rate limits and requirements
   - Test with `curl`

2. **Define the structure** in `platforms.json`
   ```json
   {
     "name": "New Platform",
     "url": "https://api.newplatform.com/users/{username}",
     "not_found_indicators": ["404", "User not found"],
     "profile_fields": [
       {"name": "field_name", "path": "/json/path"}
     ]
   }
   ```

3. **Test it**
   ```bash
   ./osintmaster -u testuser
   ```

See [API_CONFIGURATION.md](API_CONFIGURATION.md#adding-new-platforms) for detailed instructions.

---

## Platform Status Legend

- ✅ **Active** - Tested and working
- ⚠️ **Limited** - Requires authentication or has limitations
- 🔧 **In Development** - Not fully integrated
- ⛔ **Deprecated** - No longer maintained

---

For more information, see:
- [API_CONFIGURATION.md](API_CONFIGURATION.md) - Detailed setup guide
- [README.md](README.md) - Main project documentation
