# mitmproxy OpenPIMS Addon

Ein mitmproxy-Addon, das automatisch einen `x-openpims` Header zu allen HTTP-Requests hinzufügt und den Proxy mit HTTP Basic Auth schützt.

## Features

- 🔐 **Proxy-Schutz**: HTTP Basic Auth für den mitmproxy
- 📨 **Header-Injection**: Fügt `x-openpims` Header zu allen Requests hinzu
- 🔄 **Automatische Updates**: Lädt den Header-Wert alle 5 Minuten neu
- 💾 **Intelligent Caching**: Vermeidet unnötige API-Calls
- 🛡️ **Fehlerbehandlung**: Robuste Behandlung von Netzwerkproblemen
- ⏱️ **Retry-Logik**: Wartet nach Fehlern bevor erneut versucht wird

## Installation

### Voraussetzungen

```bash
pip install mitmproxy requests
```

### Repository klonen

```bash
git clone <repository-url>
cd mitmproxy-openpims-addon
```

## Verwendung

### Basis-Verwendung

```bash
mitmdump -s openpims_addon.py --set username=deine@email.de --set password=dein_passwort
```

### Mit Web-Interface

```bash
mitmweb -s openpims_addon.py --set username=deine@email.de --set password=dein_passwort
```

### Mit erweiterten Optionen

```bash
mitmdump -s openpims_addon.py \
  --set username=deine@email.de \
  --set password=dein_passwort \
  --set openpims_url=https://me.openpims.de \
  -v  # Verbose Logging
```

## Konfiguration

### Verfügbare Optionen

| Option | Beschreibung | Standard | Erforderlich |
|--------|--------------|----------|--------------|
| `username` | E-Mail-Adresse für Basic Auth | - | ✅ |
| `password` | Passwort für Basic Auth | - | ✅ |
| `openpims_url` | OpenPIMS Service URL | `https://me.openpims.de` | ❌ |

### Beispiel-Konfiguration

```bash
# Minimale Konfiguration
mitmdump -s openpims_addon.py \
  --set username=user@example.com \
  --set password=geheim123

# Mit custom URL
mitmdump -s openpims_addon.py \
  --set username=user@example.com \
  --set password=geheim123 \
  --set openpims_url=https://custom-openpims.de
```

## Funktionsweise

1. **Startup**: Das Addon lädt beim Start den OpenPIMS-Wert vom konfigurierten Server
2. **Proxy Auth**: Der mitmproxy wird mit den angegebenen Credentials geschützt
3. **Header Injection**: Bei jedem Request wird der `x-openpims` Header hinzugefügt
4. **Auto-Update**: Alle 5 Minuten wird der Wert automatisch aktualisiert
5. **Fehlerbehandlung**: Bei Fehlern wartet das Addon 60 Sekunden vor dem nächsten Versuch

### Cache-Verhalten

- **Erfolgreiche Requests**: Wert wird 5 Minuten gecacht
- **Fehlgeschlagene Requests**: 60 Sekunden Wartezeit vor erneutem Versuch
- **Timeout-Behandlung**: 15 Sekunden Timeout für HTTP-Requests

## Browser-Konfiguration

### Proxy-Einstellungen

1. **HTTP-Proxy**: `127.0.0.1:8080`
2. **Benutzername**: Deine E-Mail-Adresse
3. **Passwort**: Dein Passwort
4. **HTTPS-Proxy**: `127.0.0.1:8080` (gleiche Einstellungen)

### Beispiel für Chrome

```bash
# Chrome mit Proxy starten
google-chrome --proxy-server="http://127.0.0.1:8080" --proxy-auth="user@example.com:passwort"
```

## Testing

### Verbindung testen

```bash
# Mit curl testen
curl -x http://user%40example.com:passwort@127.0.0.1:8080 -v https://httpbin.org/headers

# OpenPIMS Service direkt testen
curl -u "user@example.com:passwort" https://me.openpims.de
```

### Header-Injection verifizieren

Besuche `https://httpbin.org/headers` über den Proxy und prüfe ob der `x-openpims` Header vorhanden ist.

## Logging

### Log-Level

- **Info**: Startup-Meldungen, erfolgreiche Wert-Ladungen
- **Warning**: Timeout- und Verbindungsfehler
- **Error**: Authentifizierungsfehler, kritische Fehler
- **Debug**: Detaillierte Request/Response-Informationen

### Verbose Logging aktivieren

```bash
mitmdump -s openpims_addon.py \
  --set username=user@example.com \
  --set password=passwort \
  -v  # Aktiviert Debug-Logging
```

## Häufige Probleme

### "Maximum recursion depth exceeded"

**Problem**: Rekursionsfehler beim Start  
**Lösung**: Verwende die neueste Version des Scripts - das Problem wurde in v1.1 behoben

### "Read timed out"

**Problem**: OpenPIMS Server antwortet nicht  
**Lösung**: 
- Prüfe die Internetverbindung
- Teste den Service direkt: `curl -u "email:pass" https://me.openpims.de`
- Das Addon wartet automatisch 60 Sekunden vor erneutem Versuch

### "Authentifizierung fehlgeschlagen"

**Problem**: 401 Unauthorized vom OpenPIMS Service  
**Lösung**: 
- Prüfe E-Mail-Adresse und Passwort
- Teste die Credentials direkt mit curl
- Verwende URL-Encoding für Sonderzeichen: `@` wird zu `%40`

### "Kein OpenPIMS Wert verfügbar"

**Problem**: Header wird nicht hinzugefügt  
**Lösung**: 
- Prüfe die Logs auf Fehlermeldungen
- Stelle sicher, dass der OpenPIMS Service erreichbar ist
- Bei Debug-Logging erscheint diese Meldung häufiger (ist normal)

## Entwicklung

### Script-Struktur

```
openpims_addon.py
├── OpenPIMSAddon Class
│   ├── load()         # Optionen definieren
│   ├── configure()    # Credentials laden
│   ├── running()      # Proxy Auth aktivieren
│   ├── fetch_openpims_value()  # Wert vom Server laden
│   ├── request()      # Header zu Requests hinzufügen
│   └── response()     # Optional: Response Logging
```

### Erweiterungen

Das Script kann leicht erweitert werden:

```python
# Mehrere Header hinzufügen
flow.request.headers["x-custom-header"] = "custom-value"

# Request-Filtering
if "example.com" in flow.request.pretty_host:
    # Nur für bestimmte Domains
```

## Sicherheit

- ⚠️ **Credentials**: E-Mail und Passwort werden als Kommandozeilen-Parameter übergeben
- 🔐 **HTTPS**: Verbindungen zum OpenPIMS Service verwenden SSL/TLS
- 🛡️ **Auth**: Proxy ist durch HTTP Basic Auth geschützt
- 💾 **Speicherung**: Keine dauerharte Speicherung von Credentials

## Lizenz

MIT License - siehe LICENSE Datei für Details

## Support

Bei Problemen:

1. Prüfe die Logs auf Fehlermeldungen
2. Teste die Verbindung zum OpenPIMS Service
3. Erstelle ein Issue mit vollständigen Log-Ausgaben

---

**Version**: 1.1  
**Letzte Aktualisierung**: August 2025
