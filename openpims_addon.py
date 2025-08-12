#!/usr/bin/env python3
"""
Mitmproxy Addon für x-openpims Header mit Basic Auth Schutz

Das Addon:
1. Schützt den Proxy mit HTTP Basic Auth
2. Lädt den x-openpims Wert von me.openpims.de mit denselben Credentials
3. Fügt den x-openpims Header zu allen Requests hinzu

Usage:
mitmdump -s mitmproxy_openpims_addon.py --set username=deine@email.de --set password=dein_pass
"""

import base64
import requests
import time
import threading
from mitmproxy import http, ctx
from mitmproxy.addons import proxyauth
from typing import Optional


class OpenPIMSAddon:
    def __init__(self):
        self.openpims_value: Optional[str] = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.last_fetch_time: float = 0
        self.last_fetch_attempt: float = 0
        self.fetch_interval: int = 300  # 5 Minuten Cache
        self.retry_interval: int = 60   # 1 Minute Retry nach Fehler
        self.fetch_lock = threading.Lock()
        self.fetch_failed: bool = False

    def load(self, loader):
        """Lädt die Konfiguration"""
        loader.add_option(
            name="username",
            typespec=str,
            default="",
            help="E-Mail-Adresse für Basic Auth (Proxy und OpenPIMS Service)"
        )
        loader.add_option(
            name="password", 
            typespec=str,
            default="",
            help="Passwort für Basic Auth (Proxy und OpenPIMS Service)"
        )
        loader.add_option(
            name="openpims_url",
            typespec=str,
            default="https://me.openpims.de",
            help="OpenPIMS Service URL"
        )

    def configure(self, updates):
        """Konfiguriert das Addon"""
        self.username = ctx.options.username
        self.password = ctx.options.password
        
        if not self.username or not self.password:
            ctx.log.error("E-Mail-Adresse und Passwort müssen gesetzt werden!")
            return
            
        ctx.log.info(f"Addon konfiguriert für E-Mail: {self.username}")
        
        # Initial den OpenPIMS Wert laden
        self.fetch_openpims_value()

    def running(self):
        """Wird aufgerufen wenn mitmproxy startet"""
        if self.username and self.password:
            # Proxy Auth hier setzen um Rekursion zu vermeiden
            ctx.options.proxyauth = f"{self.username}:{self.password}"
            ctx.log.info(f"Proxy Auth aktiviert für E-Mail: {self.username}")

    def fetch_openpims_value(self) -> bool:
        """Lädt den OpenPIMS Wert vom Server"""
        if not self.username or not self.password:
            ctx.log.error("E-Mail-Adresse und Passwort nicht verfügbar")
            return False
            
        current_time = time.time()
        
        # Cache prüfen
        if (self.openpims_value and 
            current_time - self.last_fetch_time < self.fetch_interval):
            return True
            
        # Prüfen ob wir zu früh nach einem Fehler erneut versuchen
        if (self.fetch_failed and 
            current_time - self.last_fetch_attempt < self.retry_interval):
            return False
            
        with self.fetch_lock:
            # Double-check nach Lock
            if (self.openpims_value and 
                current_time - self.last_fetch_time < self.fetch_interval):
                return True
                
            # Retry-Check nach Lock
            if (self.fetch_failed and 
                current_time - self.last_fetch_attempt < self.retry_interval):
                return False
                
            try:
                ctx.log.info("Lade OpenPIMS Wert von Server...")
                self.last_fetch_attempt = current_time
                
                # Basic Auth Header erstellen
                credentials = base64.b64encode(
                    f"{self.username}:{self.password}".encode()
                ).decode()
                
                headers = {
                    "Authorization": f"Basic {credentials}",
                    "User-Agent": "mitmproxy-openpims-addon/1.0"
                }
                
                response = requests.get(
                    ctx.options.openpims_url,
                    headers=headers,
                    timeout=15,  # Erhöht auf 15 Sekunden
                    verify=True  # SSL Verifizierung
                )
                
                if response.status_code == 200:
                    self.openpims_value = response.text.strip()
                    self.last_fetch_time = current_time
                    self.fetch_failed = False
                    ctx.log.info(f"OpenPIMS Wert erfolgreich geladen: {self.openpims_value[:20]}...")
                    return True
                elif response.status_code == 401:
                    ctx.log.error("Authentifizierung fehlgeschlagen - prüfe E-Mail-Adresse/Passwort")
                    self.fetch_failed = True
                    return False
                else:
                    ctx.log.error(f"HTTP Fehler beim Laden des OpenPIMS Werts: {response.status_code}")
                    self.fetch_failed = True
                    return False
                    
            except requests.exceptions.Timeout:
                ctx.log.warn(f"Timeout beim Laden des OpenPIMS Werts - Retry in {self.retry_interval} Sekunden")
                self.fetch_failed = True
                return False
            except requests.exceptions.ConnectionError:
                ctx.log.warn(f"Verbindungsfehler zu {ctx.options.openpims_url} - Server nicht erreichbar")
                self.fetch_failed = True
                return False
            except requests.exceptions.RequestException as e:
                ctx.log.error(f"Netzwerkfehler beim Laden des OpenPIMS Werts: {e}")
                self.fetch_failed = True
                return False
            except Exception as e:
                ctx.log.error(f"Unerwarteter Fehler: {e}")
                self.fetch_failed = True
                return False

    def request(self, flow: http.HTTPFlow) -> None:
        """Wird für jeden Request aufgerufen"""
        # Nur versuchen zu laden wenn noch kein Wert vorhanden oder Cache abgelaufen
        current_time = time.time()
        should_fetch = (
            not self.openpims_value or 
            (current_time - self.last_fetch_time >= self.fetch_interval)
        ) and (
            not self.fetch_failed or 
            (current_time - self.last_fetch_attempt >= self.retry_interval)
        )
        
        if should_fetch:
            success = self.fetch_openpims_value()
            if not success and not self.openpims_value:
                ctx.log.debug(f"Kein OpenPIMS Wert verfügbar für {flow.request.pretty_host}")
                return
            
        # Header hinzufügen falls Wert verfügbar
        if self.openpims_value:
            flow.request.headers["x-openpims"] = self.openpims_value
            ctx.log.debug(f"x-openpims Header hinzugefügt zu {flow.request.pretty_host}")
        else:
            ctx.log.debug(f"Kein OpenPIMS Wert verfügbar für {flow.request.pretty_host}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Optional: Response Logging"""
        # Nur Debug-Logging wenn explizit gewünscht
        ctx.log.debug(f"Response {flow.response.status_code} für {flow.request.pretty_host}")


# Addon Instanz erstellen
addons = [
    OpenPIMSAddon()
]


if __name__ == "__main__":
    """
    Zum Testen des Scripts direkt ausführbar
    """
    print("Mitmproxy OpenPIMS Addon")
    print("Verwendung:")
    print("mitmdump -s mitmproxy_openpims_addon.py --set username=deine@email.de --set password=dein_pass")
    print("\nOptionale Parameter:")
    print("--set openpims_url=https://andere-url.de")
    print("-v  # Für verbose Logging")
