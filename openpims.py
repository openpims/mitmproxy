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
Mitmproxy addon for deterministic x-openpims header with cookie filtering (Passwordless version)

The addon:
1. Uses OpenPIMS credentials (userId, token, domain) from command line
2. Generates domain-specific deterministic subdomains with HMAC-SHA256
3. Adds x-openpims and X-OpenPIMS headers to all requests
4. Filters cookies based on domain-specific consent data from OpenPIMS service
5. Optional: Protects the proxy with HTTP Basic Auth

The subdomains are:
- Deterministic (same input → same subdomain within a day)
- Domain-specific (each visited domain gets its own URL)
- Daily rotating (subdomain is regenerated at midnight UTC)

Cookie filtering:
- Fetches cookie consent data from OpenPIMS service for each domain
- Filters both incoming and outgoing cookies based on consent settings
- Only allows cookies where checked=1 in the consent data

Usage:
mitmdump -s openpims.py --set user_id=123 --set token=your_32_char_token --set app_domain=openpims.de

Get your credentials from the OpenPIMS dashboard after logging in via magic link.
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
        self.last_fetch_time: float = 0
        self.fetch_failed: bool = False

        # Cookie consent caching
        self.cookie_consent_cache: Dict[str, List[Dict]] = {}  # domain -> consent data
        self.cookie_consent_fetch_times: Dict[str, float] = {}  # domain -> last fetch time
        self.cookie_consent_lock = threading.Lock()
        self.cookie_consent_cache_interval: int = 300  # 5 minutes cache for cookie consent

    def load(self, loader):
        """Loads the configuration"""
        loader.add_option(
            name="user_id",
            typespec=str,
            default="",
            help="OpenPIMS User ID (from dashboard)"
        )
        loader.add_option(
            name="token",
            typespec=str,
            default="",
            help="OpenPIMS Token (32 characters, from dashboard)"
        )
        loader.add_option(
            name="app_domain",
            typespec=str,
            default="openpims.de",
            help="OpenPIMS App Domain"
        )
        loader.add_option(
            name="proxy_username",
            typespec=str,
            default="",
            help="Optional: Username for proxy authentication"
        )
        loader.add_option(
            name="proxy_password",
            typespec=str,
            default="",
            help="Optional: Password for proxy authentication"
        )

    def configure(self, updates):
        """Configures the addon"""
        # Get OpenPIMS credentials from command line
        self.user_id = ctx.options.user_id
        self.token = ctx.options.token
        self.app_domain = ctx.options.app_domain

        if not self.user_id or not self.token or not self.app_domain:
            ctx.log.error("user_id, token, and app_domain must be set!")
            ctx.log.error("Get these values from your OpenPIMS dashboard")
            return

        ctx.log.info(f"Addon configured: User ID {self.user_id}, Domain {self.app_domain}")

        # No need to fetch from server - we have everything directly
        self.last_fetch_time = time.time()
        self.fetch_failed = False

    def running(self):
        """Called when mitmproxy starts"""
        proxy_user = ctx.options.proxy_username
        proxy_pass = ctx.options.proxy_password

        if proxy_user and proxy_pass:
            # Optional: Set proxy auth if provided
            ctx.options.proxyauth = f"{proxy_user}:{proxy_pass}"
            ctx.log.info(f"Proxy auth activated for user: {proxy_user}")

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

    # fetch_openpims_value() removed - credentials are now provided directly via command line

    def request(self, flow: http.HTTPFlow) -> None:
        """Called for every request - adds headers and filters outgoing cookies"""
        # Check if we have all required data
        if not all([self.user_id, self.token, self.app_domain]):
            ctx.log.debug(f"No OpenPIMS data configured for {flow.request.pretty_host}")
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

                # Add OpenPIMS signal to User-Agent
                if "User-Agent" in flow.request.headers:
                    original_ua = flow.request.headers["User-Agent"]
                    # Only append if not already present
                    if "OpenPIMS" not in original_ua:
                        flow.request.headers["User-Agent"] = f"{original_ua} OpenPIMS/2.0 ({openpims_url})"
                else:
                    # No User-Agent present, create one
                    flow.request.headers["User-Agent"] = f"mitmproxy OpenPIMS/2.0 ({openpims_url})"

                ctx.log.debug(f"OpenPIMS headers and User-Agent added to {flow.request.pretty_host}: {openpims_url}")

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
    print("OpenPIMS Mitmproxy Addon - Passwordless Version (v3.0)")
    print("="*60)
    print("\nUsage:")
    print("mitmdump -s openpims.py \\")
    print("  --set user_id=YOUR_USER_ID \\")
    print("  --set token=YOUR_32_CHAR_TOKEN \\")
    print("  --set app_domain=openpims.de")
    print("\nGet your credentials:")
    print("1. Visit https://openpims.de/login")
    print("2. Login via magic link (no password needed)")
    print("3. Copy userId, token, and domain from dashboard")
    print("\nOptional proxy authentication:")
    print("--set proxy_username=user --set proxy_password=pass")
    print("\nVerbose logging:")
    print("-v")
