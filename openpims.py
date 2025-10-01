#!/usr/bin/env python3
# Copyright 2025 OpenPIMS Contributors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Mitmproxy addon for deterministic x-openpims header with Basic Auth protection and cookie filtering

The addon:
1. Protects the proxy with HTTP Basic Auth
2. Loads authentication data (userId, token, domain) from me.openpims.de
3. Generates domain-specific deterministic subdomains with HMAC-SHA256
4. Adds x-openpims and X-OpenPIMS headers to all requests
5. Filters cookies based on domain-specific consent data from OpenPIMS service

The subdomains are:
- Deterministic (same input → same subdomain within a day)
- Domain-specific (each visited domain gets its own URL)
- Daily rotating (subdomain is regenerated at midnight UTC)

Cookie filtering:
- Fetches cookie consent data from OpenPIMS service for each domain
- Filters both incoming and outgoing cookies based on consent settings
- Only allows cookies where checked=1 in the consent data

Usage:
mitmdump -s openpims.py --set username=your@email.com --set password=your_pass
"""

import base64
import requests
import time
import threading
import hashlib
import hmac
import json
import re
from urllib.parse import quote
from typing import Optional, Dict, List

# Try to import mitmproxy, if not available show usage
try:
    from mitmproxy import http, ctx
    from mitmproxy.addons import proxyauth
    MITMPROXY_AVAILABLE = True
except ImportError:
    # Only needed when running the script directly for testing
    MITMPROXY_AVAILABLE = False
    # Create dummy classes for type hints when mitmproxy is not installed
    class http:
        class HTTPFlow:
            pass
    class ctx:
        log = None
        options = None


class OpenPIMS:
    def __init__(self):
        self.user_id: Optional[str] = None
        self.token: Optional[str] = None
        self.app_domain: Optional[str] = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.last_fetch_time: float = 0
        self.last_fetch_attempt: float = 0
        self.fetch_interval: int = 300  # 5 minutes cache
        self.retry_interval: int = 60   # 1 minute retry after error
        self.fetch_lock = threading.Lock()
        self.fetch_failed: bool = False

        # Cookie consent caching
        self.cookie_consent_cache: Dict[str, List[Dict]] = {}  # domain -> consent data
        self.cookie_consent_fetch_times: Dict[str, float] = {}  # domain -> last fetch time
        self.cookie_consent_lock = threading.Lock()
        self.cookie_consent_cache_interval: int = 300  # 5 minutes cache for cookie consent

    def load(self, loader):
        """Loads the configuration"""
        loader.add_option(
            name="username",
            typespec=str,
            default="",
            help="Email address for Basic Auth (proxy and OpenPIMS service)"
        )
        loader.add_option(
            name="password",
            typespec=str,
            default="",
            help="Password for Basic Auth (proxy and OpenPIMS service)"
        )
        loader.add_option(
            name="openpims_url",
            typespec=str,
            default="https://me.openpims.de",
            help="OpenPIMS Service URL"
        )

    def configure(self, updates):
        """Configures the addon"""
        self.username = ctx.options.username
        self.password = ctx.options.password

        if not self.username or not self.password:
            ctx.log.error("Email address and password must be set!")
            return

        ctx.log.info(f"Addon configured for email: {self.username}")

        # Initially load the OpenPIMS value
        self.fetch_openpims_value()

    def running(self):
        """Called when mitmproxy starts"""
        if self.username and self.password:
            # Set proxy auth here to avoid recursion
            ctx.options.proxyauth = f"{self.username}:{self.password}"
            ctx.log.info(f"Proxy auth activated for email: {self.username}")

    def generate_deterministic_subdomain(self, domain: str) -> Optional[str]:
        """Generates deterministic subdomain with HMAC-SHA256"""
        if not self.user_id or not self.token:
            return None

        # Day timestamp (rotates daily)
        day_timestamp = int(time.time()) // 86400

        # Message for HMAC
        message = f"{self.user_id}{domain}{day_timestamp}"

        # HMAC-SHA256 with token as key
        h = hmac.new(
            self.token.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        )

        # Hex string (first 32 characters for DNS compatibility)
        return h.hexdigest()[:32]

    def fetch_cookie_consent_data(self, domain: str, subdomain: str) -> List[Dict]:
        """Fetches cookie consent data for a domain from OpenPIMS service"""
        current_time = time.time()

        # Check cache
        with self.cookie_consent_lock:
            if domain in self.cookie_consent_cache:
                last_fetch = self.cookie_consent_fetch_times.get(domain, 0)
                if current_time - last_fetch < self.cookie_consent_cache_interval:
                    return self.cookie_consent_cache[domain]

        try:
            # Construct the URL to fetch cookie consent data
            consent_url = f"https://{subdomain}.{self.app_domain}/?url=https://{domain}/openpims.json"

            ctx.log.debug(f"Fetching cookie consent data from: {consent_url}")

            # Optionally disable SSL verification for .test domains
            verify_ssl = not self.app_domain.endswith('.test')

            response = requests.get(
                consent_url,
                timeout=5,  # Shorter timeout for consent data
                verify=verify_ssl
            )

            if response.status_code == 200:
                try:
                    consent_data = response.json()

                    # Validate that it's a list
                    if not isinstance(consent_data, list):
                        ctx.log.warn(f"Invalid cookie consent data format for {domain}: not a list")
                        consent_data = []

                    # Update cache
                    with self.cookie_consent_lock:
                        self.cookie_consent_cache[domain] = consent_data
                        self.cookie_consent_fetch_times[domain] = current_time

                    ctx.log.debug(f"Cookie consent data loaded for {domain}: {len(consent_data)} rules")
                    return consent_data

                except json.JSONDecodeError:
                    ctx.log.warn(f"Invalid JSON in cookie consent data for {domain}")
                    return []
            else:
                ctx.log.debug(f"Could not fetch cookie consent data for {domain}: HTTP {response.status_code}")
                return []

        except requests.exceptions.Timeout:
            ctx.log.debug(f"Timeout fetching cookie consent data for {domain}")
            return []
        except Exception as e:
            ctx.log.debug(f"Error fetching cookie consent data for {domain}: {e}")
            return []

    def filter_cookies_in_header(self, cookie_header: str, consent_data: List[Dict], is_set_cookie: bool = False) -> Optional[str]:
        """Filters cookies based on consent data

        Args:
            cookie_header: The Cookie or Set-Cookie header value
            consent_data: List of consent rules with 'cookie' and 'checked' fields
            is_set_cookie: True if this is a Set-Cookie header, False for Cookie header

        Returns:
            Filtered cookie string or None if all cookies are filtered out
        """
        if not consent_data:
            # If no consent data, don't filter anything
            return cookie_header

        # Create a set of allowed cookie names
        allowed_cookies = {
            rule['cookie'] for rule in consent_data
            if rule.get('checked') == 1
        }

        if not allowed_cookies:
            # If no cookies are allowed, filter out everything
            return None

        if is_set_cookie:
            # For Set-Cookie headers, check if the cookie name is allowed
            cookie_name = cookie_header.split('=')[0].strip()
            if cookie_name in allowed_cookies:
                return cookie_header
            else:
                return None
        else:
            # For Cookie headers, filter individual cookies
            cookies = []
            for cookie_pair in cookie_header.split(';'):
                cookie_pair = cookie_pair.strip()
                if '=' in cookie_pair:
                    cookie_name = cookie_pair.split('=')[0].strip()
                    if cookie_name in allowed_cookies:
                        cookies.append(cookie_pair)

            if cookies:
                return '; '.join(cookies)
            else:
                return None

    def fetch_openpims_value(self) -> bool:
        """Loads the OpenPIMS value from the server"""
        if not self.username or not self.password:
            ctx.log.error("Email address and password not available")
            return False

        current_time = time.time()

        # Check cache
        if (self.user_id and self.token and self.app_domain and
            current_time - self.last_fetch_time < self.fetch_interval):
            return True

        # Check if we're retrying too soon after an error
        if (self.fetch_failed and
            current_time - self.last_fetch_attempt < self.retry_interval):
            return False

        with self.fetch_lock:
            # Double-check after lock
            if (self.user_id and self.token and self.app_domain and
                current_time - self.last_fetch_time < self.fetch_interval):
                return True

            # Retry check after lock
            if (self.fetch_failed and
                current_time - self.last_fetch_attempt < self.retry_interval):
                return False

            try:
                ctx.log.info("Loading OpenPIMS value from server...")
                self.last_fetch_attempt = current_time

                # Create Basic Auth header
                credentials = base64.b64encode(
                    f"{self.username}:{self.password}".encode()
                ).decode()
                
                headers = {
                    "Authorization": f"Basic {credentials}",
                    "User-Agent": "mitmproxy-openpims-addon/1.0"
                }
                
                # Optionally disable SSL verification for .test domains
                verify_ssl = not ctx.options.openpims_url.endswith('.test')

                response = requests.get(
                    ctx.options.openpims_url,
                    headers=headers,
                    timeout=15,  # Increased to 15 seconds
                    verify=verify_ssl  # SSL verification (disabled for .test)
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        self.user_id = data.get('userId')
                        self.token = data.get('token')
                        self.app_domain = data.get('domain')

                        if not all([self.user_id, self.token, self.app_domain]):
                            ctx.log.error("Incomplete data received from server")
                            self.fetch_failed = True
                            return False

                        self.last_fetch_time = current_time
                        self.fetch_failed = False
                        ctx.log.info(f"OpenPIMS data successfully loaded: User {self.user_id}, Domain {self.app_domain}")
                        return True
                    except json.JSONDecodeError:
                        ctx.log.error("Error parsing JSON response")
                        self.fetch_failed = True
                        return False
                elif response.status_code == 401:
                    ctx.log.error("Authentication failed - check email address/password")
                    self.fetch_failed = True
                    return False
                else:
                    ctx.log.error(f"HTTP error loading OpenPIMS value: {response.status_code}")
                    self.fetch_failed = True
                    return False

            except requests.exceptions.Timeout:
                ctx.log.warn(f"Timeout loading OpenPIMS value - retry in {self.retry_interval} seconds")
                self.fetch_failed = True
                return False
            except requests.exceptions.ConnectionError:
                ctx.log.warn(f"Connection error to {ctx.options.openpims_url} - server not reachable")
                self.fetch_failed = True
                return False
            except requests.exceptions.RequestException as e:
                ctx.log.error(f"Network error loading OpenPIMS value: {e}")
                self.fetch_failed = True
                return False
            except Exception as e:
                ctx.log.error(f"Unexpected error: {e}")
                self.fetch_failed = True
                return False

    def request(self, flow: http.HTTPFlow) -> None:
        """Called for every request - adds headers and filters outgoing cookies"""
        # Only try to load if no value exists yet or cache expired
        current_time = time.time()
        should_fetch = (
            not all([self.user_id, self.token, self.app_domain]) or
            (current_time - self.last_fetch_time >= self.fetch_interval)
        ) and (
            not self.fetch_failed or
            (current_time - self.last_fetch_attempt >= self.retry_interval)
        )

        if should_fetch:
            success = self.fetch_openpims_value()
            if not success and not all([self.user_id, self.token, self.app_domain]):
                ctx.log.debug(f"No OpenPIMS data available for {flow.request.pretty_host}")
                return

        # Generate domain-specific subdomain
        if self.user_id and self.token and self.app_domain:
            subdomain = self.generate_deterministic_subdomain(flow.request.pretty_host)
            if subdomain:
                # Add header with deterministic URL
                openpims_url = f"https://{subdomain}.{self.app_domain}"
                flow.request.headers["x-openpims"] = openpims_url

                # X-OpenPIMS header for better compatibility
                flow.request.headers["X-OpenPIMS"] = openpims_url

                ctx.log.debug(f"OpenPIMS headers added to {flow.request.pretty_host}: {openpims_url}")

                # Fetch cookie consent data and filter outgoing cookies
                consent_data = self.fetch_cookie_consent_data(flow.request.pretty_host, subdomain)
                if consent_data:
                    # Filter Cookie header
                    if "Cookie" in flow.request.headers:
                        original_cookies = flow.request.headers["Cookie"]
                        filtered_cookies = self.filter_cookies_in_header(original_cookies, consent_data, is_set_cookie=False)

                        if filtered_cookies:
                            flow.request.headers["Cookie"] = filtered_cookies
                            ctx.log.debug(f"Filtered outgoing cookies for {flow.request.pretty_host}")
                        else:
                            del flow.request.headers["Cookie"]
                            ctx.log.debug(f"Removed all outgoing cookies for {flow.request.pretty_host}")
            else:
                ctx.log.debug(f"Could not generate subdomain for {flow.request.pretty_host}")
        else:
            ctx.log.debug(f"No OpenPIMS data available for {flow.request.pretty_host}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Filters incoming cookies in Set-Cookie headers"""
        # Filter incoming cookies if we have OpenPIMS data
        if self.user_id and self.token and self.app_domain:
            subdomain = self.generate_deterministic_subdomain(flow.request.pretty_host)
            if subdomain:
                # Fetch cookie consent data
                consent_data = self.fetch_cookie_consent_data(flow.request.pretty_host, subdomain)
                if consent_data:
                    # Filter Set-Cookie headers
                    if "Set-Cookie" in flow.response.headers:
                        # mitmproxy stores multiple Set-Cookie headers as a list
                        set_cookie_headers = flow.response.headers.get_all("Set-Cookie")
                        filtered_headers = []

                        for cookie_header in set_cookie_headers:
                            filtered = self.filter_cookies_in_header(cookie_header, consent_data, is_set_cookie=True)
                            if filtered:
                                filtered_headers.append(filtered)

                        # Update headers
                        del flow.response.headers["Set-Cookie"]
                        for header in filtered_headers:
                            flow.response.headers.add("Set-Cookie", header)

                        if filtered_headers:
                            ctx.log.debug(f"Filtered incoming cookies for {flow.request.pretty_host}: {len(filtered_headers)} cookies allowed")
                        else:
                            ctx.log.debug(f"Removed all incoming cookies for {flow.request.pretty_host}")

        # Debug logging
        ctx.log.debug(f"Response {flow.response.status_code} for {flow.request.pretty_host}")


# Create addon instance only if mitmproxy is available
if MITMPROXY_AVAILABLE:
    addons = [
        OpenPIMS()
    ]


if __name__ == "__main__":
    """
    Script can be run directly for testing
    """
    print("OpenPIMS Mitmproxy Addon - Deterministic HMAC-SHA256 with Cookie Filtering")
    print("Usage:")
    print("mitmdump -s openpims.py --set username=your@email.com --set password=your_pass")
    print("\nOptional parameters:")
    print("--set openpims_url=https://other-url.com")
    print("-v  # For verbose logging")
