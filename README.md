# GhostSurf

Privacy browser with multi-profile isolation, per-profile proxy routing, and REST API for AI agent control. Built for managing multiple Reddit accounts without cross-contamination.

## Features

- **Multi-profile isolation** — each profile gets its own cookies, local storage, cache, and browsing history
- **Per-profile proxy** — HTTP and SOCKS5 proxy support with username/password auth (tested with BeeProxy)
- **Privacy hardening** — WebRTC blocking, canvas/WebGL fingerprint spoofing, navigator API surface reduction
- **REST API** — control the browser programmatically (OpenClaw compatible)
- **Dark UI** — tabbed browsing with profile color coding and keyboard shortcuts

## Quick Start

```bash
# Clone
git clone https://github.com/indexsy/ghostsurf.git
cd ghostsurf

# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp config.example.json config.json
# Edit config.json with your proxy credentials and profile settings

# Run
./run.sh
```

## SOP: Setting Up Reddit Profiles

### 1. Create your config

Copy `config.example.json` to `config.json` and add a profile for each Reddit account:

```json
{
  "reddit-account1": {
    "name": "Reddit Account 1",
    "color": "#4ecca3",
    "proxy": {
      "enabled": true,
      "type": "http",
      "host": "38.180.149.107",
      "port": 17521,
      "username": "logiiproxy123-country-CA-city-vancouver-ssid-UNIQUE_ID_1-sst-1",
      "password": "your-password"
    },
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "homepage": "https://www.reddit.com",
    "privacy": {
      "block_webrtc": true,
      "spoof_canvas": true,
      "spoof_webgl": true,
      "block_third_party_cookies": true,
      "do_not_track": true
    },
    "notes": "u/account1"
  }
}
```

**Key points:**
- Each profile needs a **unique `ssid`** in the proxy username to get a different sticky IP
- Use **different user agents** per profile so Reddit sees different browser fingerprints
- The `notes` field is displayed in the UI — use it to label which Reddit account

### 2. Launch and log in

```bash
./run.sh
```

1. Select a profile from the dropdown
2. Navigate to reddit.com and log into that account
3. The cookies are saved to that profile's isolated storage
4. Switch to the next profile and repeat

### 3. Daily use

- Select the profile for the account you want to use
- Each profile maintains its own logged-in session
- Switch profiles via the dropdown or the menu (profiles open in new tabs)
- Use `Cmd+T` for new tabs, `Cmd+W` to close

### BeeProxy Username Format

```
logiiproxy123-country-{CC}-city-{city}-ssid-{session_id}-sst-{session_type}
```

| Field | Example | Notes |
|---|---|---|
| `country` | `CA`, `US` | ISO country code |
| `city` | `vancouver`, `chicago` | Lowercase city name |
| `ssid` | `myaccount01` | Unique per profile for different sticky IPs |
| `sst` | `1` | Session type (1 = sticky) |

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Cmd+T` | New tab |
| `Cmd+W` | Close tab |
| `Cmd+L` | Focus URL bar |
| `Cmd+R` | Reload |
| `Cmd+Shift+N` | New private tab (no persistence) |

## REST API

The browser runs an API server on `http://127.0.0.1:9378` for programmatic control.

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/status` | Browser status, active profile, tab count |
| `GET` | `/profiles` | List all profiles with configs |
| `GET` | `/tabs` | List open tabs (URL, title) |
| `GET` | `/snapshot` | Full state snapshot |
| `POST` | `/navigate` | Navigate tab to URL `{"url": "...", "tab_index": 0}` |
| `POST` | `/tabs` | Open new tab `{"url": "..."}` |
| `POST` | `/tabs/close` | Close tab `{"index": 0}` |
| `POST` | `/profiles/switch` | Switch profile `{"profile_id": "..."}` |
| `POST` | `/profiles` | Create profile `{"id": "...", "config": {...}}` |
| `DELETE` | `/profiles/{id}` | Delete profile |

### Example

```bash
# Check status
curl http://127.0.0.1:9378/status

# Switch to a profile
curl -X POST http://127.0.0.1:9378/profiles/switch \
  -H "Content-Type: application/json" \
  -d '{"profile_id": "reddit-alt1"}'

# Open reddit in new tab
curl -X POST http://127.0.0.1:9378/tabs \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.reddit.com"}'
```

### OpenClaw Integration

The `openclaw.plugin.json` file is included. Point OpenClaw at `http://127.0.0.1:9378` to let it control profiles, tabs, and navigation.

## Architecture

```
Chromium (QtWebEngine)
    │
    ▼
127.0.0.1:18899 (Local Proxy Relay)
    │
    ├── Profile has proxy? ──▶ Upstream proxy (BeeProxy gateway)
    │                              with Proxy-Authorization header
    │
    └── No proxy? ──────────▶ Direct connection
```

QtWebEngine's Chromium ignores `QNetworkProxy`. The relay is a local TCP server that Chromium connects to via `--proxy-server`. On profile switch, the relay swaps the upstream target dynamically — no browser restart needed.

## Privacy Features

- **WebRTC blocking** — prevents IP leak through `RTCPeerConnection`
- **Canvas fingerprint spoofing** — adds noise to `toDataURL()` output
- **WebGL renderer spoofing** — reports generic Intel renderer
- **Navigator spoofing** — normalizes `hardwareConcurrency`, `deviceMemory`, `plugins`, `languages`
- **Battery API blocking** — removes `getBattery()`
- **DuckDuckGo** default search engine
- **Per-profile user agent** rotation

## File Structure

```
ghostsurf/
├── browser.py              # Main application
├── run.sh                  # Launch script
├── config.json             # Your profiles (gitignored)
├── config.example.json     # Example config template
├── openclaw.plugin.json    # OpenClaw plugin definition
├── requirements.txt        # Python dependencies
└── profiles/               # Profile data storage (gitignored)
    ├── default/
    ├── reddit-van-1/
    └── reddit-van-2/
```
