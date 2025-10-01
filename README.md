# mitmproxy OpenPIMS Addon

A mitmproxy addon that automatically adds domain-specific deterministic `x-openpims` headers to all HTTP requests and protects the proxy with HTTP Basic Auth.

## Features

- 🔐 **Proxy Protection**: HTTP Basic Auth for mitmproxy
- 🔑 **Deterministic URLs**: HMAC-SHA256 based subdomain generation
- 🌐 **Domain-specific**: Each visited domain gets its own OpenPIMS URL
- 📨 **Header Injection**: Adds `x-openpims` and `X-OpenPIMS` headers to all requests
- 🔄 **Daily Rotation**: Subdomains are regenerated at midnight UTC
- 💾 **Intelligent Caching**: Auth data is cached for 5 minutes
- 🛡️ **Error Handling**: Robust handling of network problems
- ⏱️ **Retry Logic**: Waits after errors before trying again

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

## Usage

### Basic Usage

```bash
mitmdump -s openpims_addon.py --set username=your@email.com --set password=your_password
```

### With Web Interface

```bash
mitmweb -s openpims_addon.py --set username=your@email.com --set password=your_password
```

### With Advanced Options

```bash
mitmdump -s openpims_addon.py \
  --set username=your@email.com \
  --set password=your_password \
  --set openpims_url=https://me.openpims.de \
  -v  # Verbose Logging
```

## Configuration

### Available Options

| Option | Description | Default | Required |
|--------|-------------|---------|----------|
| `username` | Email address for Basic Auth | - | ✅ |
| `password` | Password for Basic Auth | - | ✅ |
| `openpims_url` | OpenPIMS Service URL | `https://me.openpims.de` | ❌ |

### Example Configuration

```bash
# Minimal configuration
mitmdump -s openpims_addon.py \
  --set username=user@example.com \
  --set password=secret123

# With custom URL
mitmdump -s openpims_addon.py \
  --set username=user@example.com \
  --set password=secret123 \
  --set openpims_url=https://custom-openpims.de
```

## How It Works

1. **Startup**: The addon loads authentication data (userId, token, domain) from the OpenPIMS server at startup
2. **Proxy Auth**: mitmproxy is protected with the provided credentials
3. **Subdomain Generation**: A deterministic subdomain is generated for each visited domain using HMAC-SHA256
4. **Header Injection**: `x-openpims` and `X-OpenPIMS` headers with the domain-specific URL are added to each request
5. **Daily Rotation**: Subdomains are automatically regenerated at midnight UTC (based on day timestamp)
6. **Auto-Update**: Auth data is refreshed from the server every 5 minutes
7. **Error Handling**: The addon waits 60 seconds before retrying after errors

### Deterministic Subdomain Generation

The addon generates a unique subdomain for each visited domain:

- **Algorithm**: HMAC-SHA256 with token as key
- **Message**: `userId + domain + dayTimestamp`
- **Output**: 32-character hex string (DNS-compatible)
- **Format**: `https://{subdomain}.{appDomain}`

### Cache Behavior

- **Auth Data**: Cached for 5 minutes
- **Failed Requests**: 60-second wait before retry
- **Timeout Handling**: 15-second timeout for HTTP requests

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
# Test with curl
curl -x http://user%40example.com:password@127.0.0.1:8080 -v https://httpbin.org/headers

# Test OpenPIMS service directly
curl -u "user@example.com:password" https://me.openpims.de
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
mitmdump -s openpims_addon.py \
  --set username=user@example.com \
  --set password=password \
  -v  # Enables debug logging
```

## Common Problems

### "Maximum recursion depth exceeded"

**Problem**: Recursion error at startup
**Solution**: Use the latest version of the script - this issue was fixed in v1.1

### "Read timed out"

**Problem**: OpenPIMS server not responding
**Solution**:
- Check internet connection
- Test the service directly: `curl -u "email:pass" https://me.openpims.de`
- The addon automatically waits 60 seconds before retrying

### "Authentication failed"

**Problem**: 401 Unauthorized from OpenPIMS service
**Solution**:
- Check email address and password
- Test credentials directly with curl
- Use URL encoding for special characters: `@` becomes `%40`

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
openpims_addon.py
├── OpenPIMSAddon Class
│   ├── load()         # Define options
│   ├── configure()    # Load credentials
│   ├── running()      # Activate proxy auth
│   ├── generate_deterministic_subdomain()  # Generate HMAC-SHA256 subdomain
│   ├── fetch_openpims_value()  # Load auth data (userId, token, domain) from server
│   ├── request()      # Add domain-specific headers to requests
│   └── response()     # Optional: Response logging
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

- ⚠️ **Credentials**: Email and password are passed as command-line parameters
- 🔐 **HTTPS**: Connections to OpenPIMS service use SSL/TLS
- 🛡️ **Auth**: Proxy is protected by HTTP Basic Auth
- 🔑 **HMAC**: Token is only used as HMAC key, never sent in plaintext
- 🌐 **Domain Isolation**: Each domain gets its own unique subdomain
- 💾 **Storage**: No persistent storage of credentials

## License

MIT License - see LICENSE file for details

## Support

For issues:

1. Check logs for error messages
2. Test connection to OpenPIMS service
3. Create an issue with complete log output

---

**Version**: 2.0
**Last Updated**: October 2025
**Changes**: Deterministic domain-specific subdomains with HMAC-SHA256
