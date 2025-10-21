# mitmproxy OpenPIMS Addon (Passwordless v3.0)

A mitmproxy addon that automatically adds domain-specific deterministic `x-openpims` headers to all HTTP requests and filters cookies based on consent data. **Now passwordless** - no more email/password needed!

## Features

- 🚫 **Passwordless**: Use userId + token directly from dashboard
- 🔑 **Deterministic URLs**: HMAC-SHA256 based subdomain generation
- 🌐 **Domain-specific**: Each visited domain gets its own OpenPIMS URL
- 📨 **Header Injection**: Adds `x-openpims` and `X-OpenPIMS` headers to all requests
- 🍪 **Cookie Filtering**: Filters cookies based on domain-specific consent data
- 🔄 **Daily Rotation**: Subdomains are regenerated at midnight UTC
- 💾 **Intelligent Caching**: Cookie consent cached for 5 minutes
- 🔐 **Optional Proxy Auth**: Protect proxy with HTTP Basic Auth (optional)
- 🛡️ **Error Handling**: Robust handling of network problems

## Installation

### Prerequisites

```bash
# Install from requirements.txt
pip install -r requirements.txt

# Or install manually
pip install mitmproxy requests
```

### Clone Repository

```bash
git clone <repository-url>
cd mitmproxy-openpims-addon
```

## Getting Your Credentials

**New passwordless flow:**

1. Visit your OpenPIMS provider login (e.g., `https://openpims.de/login` or `https://openpims.eu/login`)
2. Enter your email address
3. Click magic link from email (no password needed!)
4. Copy these values from your dashboard:
   - **User ID**: e.g. `123`
   - **Token**: 32 characters, e.g. `abc123...xyz`
   - **Domain**: Your provider's domain, e.g. `openpims.de` or `openpims.eu`

## Usage

### Basic Usage

```bash
mitmdump -s openpims.py \
  --set user_id=YOUR_USER_ID \
  --set token=YOUR_32_CHAR_TOKEN \
  --set app_domain=YOUR_PROVIDER_DOMAIN  # e.g., openpims.de or openpims.eu
```

### With Web Interface

```bash
mitmweb -s openpims.py \
  --set user_id=123 \
  --set token=abc123def456... \
  --set app_domain=openpims.de
```

### With Optional Proxy Authentication

```bash
mitmdump -s openpims.py \
  --set user_id=123 \
  --set token=abc123def456... \
  --set app_domain=openpims.de \
  --set proxy_username=myuser \
  --set proxy_password=mypass \
  -v  # Verbose Logging
```

## Configuration

### Available Options

| Option | Description | Default | Required |
|--------|-------------|---------|----------|
| `user_id` | OpenPIMS User ID from dashboard | - | ✅ |
| `token` | OpenPIMS Token (32 chars) from dashboard | - | ✅ |
| `app_domain` | OpenPIMS App Domain | `openpims.de` | ❌ |
| `proxy_username` | Optional: Username for proxy auth | - | ❌ |
| `proxy_password` | Optional: Password for proxy auth | - | ❌ |

### Example Configuration

```bash
# Minimal configuration (no proxy auth, uses default openpims.de)
mitmdump -s openpims.py \
  --set user_id=123 \
  --set token=abc123def456...

# With different provider (e.g., openpims.eu)
mitmdump -s openpims.py \
  --set user_id=123 \
  --set token=abc123def456... \
  --set app_domain=openpims.eu

# With proxy authentication
mitmdump -s openpims.py \
  --set user_id=123 \
  --set token=abc123def456... \
  --set proxy_username=proxyuser \
  --set proxy_password=proxypass
```

## How It Works

1. **Startup**: The addon receives authentication data (userId, token, domain) from command line
2. **Proxy Auth (Optional)**: mitmproxy can be protected with proxy_username/proxy_password
3. **Subdomain Generation**: A deterministic subdomain is generated for each visited domain using HMAC-SHA256
4. **Header Injection**: `x-openpims` and `X-OpenPIMS` headers with the domain-specific URL are added to each request
5. **Cookie Filtering**: Fetches cookie consent data from OpenPIMS service and filters both incoming and outgoing cookies
6. **Daily Rotation**: Subdomains are automatically regenerated at midnight UTC (based on day timestamp)
7. **Caching**: Cookie consent is cached for 5 minutes per domain
8. **Error Handling**: Robust handling of network issues and timeouts

### Deterministic Subdomain Generation

The addon generates a unique subdomain for each visited domain:

- **Algorithm**: HMAC-SHA256 with token as key
- **Message**: `userId + domain + dayTimestamp`
- **Output**: 32-character hex string (DNS-compatible)
- **Format**: `https://{subdomain}.{appDomain}`

### Cookie Filtering

The addon fetches cookie consent data for each domain:

- **Consent URL**: `https://{subdomain}.{appDomain}/?url=https://{domain}/openpims.json`
- **Response Format**: JSON array with objects containing:
  - `cookie`: Name of the cookie
  - `checked`: 0 (blocked) or 1 (allowed)
- **Filtering Rules**:
  - If consent data is empty: No cookies are filtered
  - If consent data exists: Only cookies with `checked=1` are allowed
  - Both incoming (Set-Cookie) and outgoing (Cookie) headers are filtered
- **Caching**: Cookie consent data is cached for 5 minutes per domain

### Cache Behavior

- **Auth Data**: Cached for 5 minutes
- **Cookie Consent**: Cached for 5 minutes per domain
- **Failed Requests**: 60-second wait before retry
- **Timeout Handling**: 15-second timeout for HTTP requests, 5-second for consent data

## Browser Configuration

### Proxy Settings

1. **HTTP Proxy**: `127.0.0.1:8080`
2. **Username**: Your email address
3. **Password**: Your password
4. **HTTPS Proxy**: `127.0.0.1:8080` (same settings)

### Example for Chrome

```bash
# Start Chrome with proxy
google-chrome --proxy-server="http://127.0.0.1:8080" --proxy-auth="user@example.com:password"
```

## Testing

### Test Connection

```bash
# Test with curl (no proxy auth)
curl -x http://127.0.0.1:8080 -v https://httpbin.org/headers

# Test with curl (with proxy auth)
curl -x http://proxyuser:proxypass@127.0.0.1:8080 -v https://httpbin.org/headers
```

### Verify Header Injection

Visit `https://httpbin.org/headers` through the proxy and check the injected headers:

- `x-openpims`: Contains the domain-specific OpenPIMS URL
- `X-OpenPIMS`: Same value for better compatibility

The URL format is: `https://{32-char-hex}.{appDomain}` and is different for each domain.

## Logging

### Log Levels

- **Info**: Startup messages, successful value loads
- **Warning**: Timeout and connection errors
- **Error**: Authentication errors, critical failures
- **Debug**: Detailed request/response information

### Enable Verbose Logging

```bash
mitmdump -s openpims.py \
  --set username=user@example.com \
  --set password=password \
  -v  # Enables debug logging
```

## Common Problems

### "Maximum recursion depth exceeded"

**Problem**: Recursion error at startup
**Solution**: Use the latest version of the script - this issue was fixed in v1.1

### "user_id, token, and app_domain must be set!"

**Problem**: Missing credentials
**Solution**:
- Login to your provider's login page via magic link (e.g., https://openpims.de/login or https://openpims.eu/login)
- Copy userId, token, and domain from dashboard
- Use all three values in command line parameters

### "No OpenPIMS data configured"

**Problem**: Credentials not set or invalid
**Solution**:
- Double-check user_id (should be a number like `123`)
- Double-check token (should be 32 characters)
- Ensure app_domain is correct (default: `openpims.de`)

### "No OpenPIMS data available"

**Problem**: Header not being added
**Solution**:
- Check logs for error messages
- Ensure the OpenPIMS service is reachable
- Check that server returns JSON with userId, token, and domain
- This message appears more frequently with debug logging (this is normal)

## Development

### Script Structure

```
openpims.py
├── OpenPIMS Class
│   ├── load()         # Define options
│   ├── configure()    # Load credentials
│   ├── running()      # Activate proxy auth
│   ├── generate_deterministic_subdomain()  # Generate HMAC-SHA256 subdomain
│   ├── fetch_openpims_value()  # Load auth data (userId, token, domain) from server
│   ├── fetch_cookie_consent_data()  # Load cookie consent rules for domain
│   ├── filter_cookies_in_header()  # Filter cookies based on consent
│   ├── request()      # Add headers and filter outgoing cookies
│   └── response()     # Filter incoming cookies
```

### Extensions

The script can be easily extended:

```python
# Modify User-Agent
flow.request.headers["User-Agent"] += f" OpenPIMS/1.0 (+{openpims_url})"

# Request filtering
if "example.com" in flow.request.pretty_host:
    # Only for specific domains

# Implement subdomain cache (for better performance)
subdomain_cache = {}  # domain -> (subdomain, timestamp)
```

## Security

- ⚠️ **Credentials**: userId and token are passed as command-line parameters (consider using environment variables)
- 🔐 **HTTPS**: Connections to OpenPIMS service use SSL/TLS
- 🛡️ **Proxy Auth**: Optional HTTP Basic Auth for proxy protection
- 🔑 **HMAC**: Token is only used as HMAC key, never sent in plaintext
- 🌐 **Domain Isolation**: Each domain gets its own unique subdomain
- 💾 **Storage**: No persistent storage of credentials
- 🚫 **Passwordless**: No passwords stored or transmitted

## License

Apache License 2.0 - see LICENSE file for details

## Multi-Provider Support

OpenPIMS supports multiple PIMS providers. Users can have accounts on different providers:

- `openpims.de` (default)
- `openpims.eu`
- Custom self-hosted instances

Simply specify the correct `app_domain` when running mitmproxy:

```bash
# For openpims.eu users
mitmdump -s openpims.py \
  --set user_id=123 \
  --set token=abc... \
  --set app_domain=openpims.eu

# For self-hosted instances
mitmdump -s openpims.py \
  --set user_id=123 \
  --set token=abc... \
  --set app_domain=my-pims.example.com
```

## Support

For issues:

1. Check logs for error messages
2. Test connection to OpenPIMS service
3. Create an issue with complete log output

---

**Version**: 3.0
**Last Updated**: October 2025
**Changes**:
- **v3.0**: Passwordless authentication - removed email/password, now uses userId/token/domain directly
- **v2.0**: Deterministic domain-specific subdomains with HMAC-SHA256

**Multi-Provider Support**: Works with any OpenPIMS provider (openpims.de, openpims.eu, self-hosted instances)
