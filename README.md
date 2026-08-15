# Multi-WiFi Network Health Monitor (ESP32) — 

A standalone ESP32 device that continuously monitors up to **20 WiFi networks**, verifies real internet connectivity (not just router association), and sends **email + IFTTT alerts** when a network goes down — with alerts intelligently queued and delivered through whichever monitored network is currently healthy.

Configuration is done entirely through a self-hosted HTTPS dashboard served from the device's own access point — no reflashing needed to add networks, change SMTP credentials, or update login details.

---

## ⚠ Security Notice (read before publishing / forking)

This repo is meant to be safe to publish publicly. All values a real deployment needs are left as **blank placeholders** in the sketch — you fill them in on your own local copy, never in git:

- `AP_SSID` / `AP_PASSWORD` — your device's hotspot name/password
- `server_cert` / `server_key` — your own self-signed TLS certificate and private key
- `ALERT_RECIPIENT` — fallback alert email
- `IFTTT_KEY` — your IFTTT Webhooks key
- Dashboard login (`dashUser` / `dashPass`) — not hardcoded at all; set once from the device itself after first boot

**Before you push to a public repo, double-check:**
1. `server_cert` / `server_key` still say `// add yours` and don't contain a real key
2. `AP_SSID`, `AP_PASSWORD`, `ALERT_RECIPIENT`, `IFTTT_KEY` are still blank
3. You haven't committed `networks.txt`, `email.txt`, `auth.txt`, or `smtp.txt` — these are generated on the device at runtime and contain your real WiFi passwords, dashboard login, and Zoho app password. The included `.gitignore` excludes them, but double-check if you ever copy a LittleFS image into the repo.
4. Your commit history doesn't contain an earlier version with real values (if it does, scrub history or start a fresh repo before making it public)

None of the above is committed by default in this version of the code.

**Also be aware (device-level, not a repo issue):** a freshly flashed device has no dashboard login yet, so the dashboard is open without a password until you set one — see step 6 under First-Time Setup. Set credentials before leaving a live device in range of anyone else.

---

## Features

- **Monitors up to 20 WiFi networks** on a rotating 5-minute cycle
- **Two-stage health check** per network:
  1. WiFi association (30s tolerant timeout, auto channel-matched AP+STA)
  2. Real internet reachability via triple-endpoint probe (Google → Cloudflare → Google gstatic), first success wins
- **Smart alerting**
  - Alerts only fire after **3 consecutive failures** (suppresses transient blips)
  - Alerts are **queued**, never sent over the broken link itself
  - Queued alerts are flushed automatically the next time *any* monitored network comes back healthy
  - One combined email if multiple networks are down at once
  - Automatic **recovery emails** with computed downtime
- **HTTPS admin dashboard** (self-signed cert) hosted on the ESP32's own AP
  - Add/remove networks, see live status badges (Healthy / No Wifi / No Internet / Pending)
  - Set alert recipient email
  - Set SMTP sender + app password (no reflashing — stored in LittleFS)
  - Change dashboard login username/password
  - Auto-refreshing table (pauses while typing)
- **Persistent storage** (LittleFS) — networks, credentials, and SMTP config survive reboot
- **XOR-obfuscated** WiFi password storage on flash
- **Cookie-based session auth** for the dashboard

---

## Hardware

| Component | Notes |
|---|---|
| ESP32 Dev Module | Any standard ESP32 dev board |

No external sensors or wiring required — this is a pure WiFi/networking utility.

---

## Required Libraries

Install via **Sketch → Include Library → Manage Libraries**:

| Library | Author |
|---|---|
| ReadyMail | Mobizt |
| ArduinoJson | Benoit Blanchon |
| PsychicHttp | hoeken |

Also uses ESP32 core built-ins: `WiFi.h`, `WiFiClientSecure.h`, `HTTPClient.h`, `LittleFS.h`, `time.h`.

---

## Board Settings (Arduino IDE → Tools menu)

| Setting | Value |
|---|---|
| Board | ESP32 Dev Module |
| Flash Size | 4MB (FS: 2MB OTA ~1019KB) |
| Partition Scheme | Default 4MB with spiffs |
| Upload Speed | 921600 |

---

## First-Time Setup

### 1. Generate a self-signed TLS certificate

Replace the placeholders in the sketch **on your local copy only**:

```cpp
const char* server_cert = R"EOF(-----BEGIN CERTIFICATE-----
// add yours
-----END CERTIFICATE-----)EOF";

const char* server_key = R"EOF(-----BEGIN PRIVATE KEY-----
// add yours
-----END PRIVATE KEY-----)EOF";
```

A 1-year self-signed cert works fine (browsers will show a warning — click **Proceed**). Never commit your real cert/key.

### 2. Set your Access Point credentials

```cpp
#define AP_SSID        "..."
#define AP_PASSWORD    "..."
```

### 3. Set a fallback alert recipient (optional)

```cpp
#define ALERT_RECIPIENT   "your-email-here"
```

This is only used if no recipient is set later from the dashboard.

### 4. (Optional) Enable IFTTT alerts

```cpp
#define IFTTT_KEY  "your_ifttt_webhooks_key"
```

Leave as `""` to disable.

### 5. Flash the sketch

### 6. Connect to the device's AP and log in

- Connect your phone/laptop to the `AP_SSID` network
- Browse to `https://192.168.4.1/login`
- Accept the certificate warning
- **On first boot, no dashboard login exists yet, so the dashboard is reachable without a password.** The `/login` page will send you straight to the dashboard automatically in this state — that's expected, not a bug. A yellow banner on the dashboard will remind you of this. **Immediately** go to **Change Login Credentials** and set a real username/password. As soon as you save them, the open window closes and every route requires the normal cookie-based login from then on (including after reboots, since credentials persist in LittleFS).
- Until you've set credentials, treat the device's AP as unsecured — don't leave a freshly flashed unit powered on and in range of others before completing this step.

### 7. Set up Zoho SMTP (for email alerts)

1. Sign in to [Zoho Accounts](https://accounts.zoho.in)
2. Go to **Security → Application-Specific Passwords → Generate**
3. Copy the generated app password
4. On the dashboard, under **SMTP Settings**, enter your sender email + that app password
   - No reflashing required — stored in LittleFS on the device, not in the source code

### 8. Add networks to monitor

Use the **Add Network** form on the dashboard. Each network is connectivity-tested before being saved.

---

## How Monitoring Works

Every `CYCLE_MS` (default **5 minutes**), the device:

1. Iterates through every saved network
2. Attempts to connect (up to 30s, tolerant of slow DHCP/association)
3. If connected, runs the internet probe (Google → Cloudflare → gstatic)
4. Classifies status as `HEALTHY`, `NO_WIFI`, or `NO_INTERNET`
5. On 3 consecutive failures of the same type, queues an alert
6. On recovery, sends a recovery email with downtime duration
7. Whenever a network tests `HEALTHY`, flushes any alerts queued from other (still-down) networks through that live connection
8. After the full pass, if alerts are still queued and a known-healthy network exists, reconnects once more to flush the backlog
9. Restarts the AP so the dashboard remains reachable between cycles

---

## Dashboard Routes

| Route | Method | Purpose |
|---|---|---|
| `/login` | GET / POST | Login page / credential check |
| `/logout` | GET | Clear session cookie |
| `/` | GET | Main dashboard |
| `/add` | POST | Add + verify a new network |
| `/delete` | GET | Remove a network by index |
| `/saveemail` | POST | Set alert recipient |
| `/savesmtp` | POST | Set SMTP sender email + app password |
| `/saveauth` | POST | Change dashboard username/password |

All routes except `/login` require a valid session cookie (guarded via `isAuthenticated()`).

---

## Data Persistence (LittleFS)

| File | Contents |
|---|---|
| `/networks.txt` | SSID, XOR-encrypted password, status, alert state, timestamps (CSV per line) |
| `/email.txt` | Alert recipient email |
| `/auth.txt` | Dashboard username + password |
| `/smtp.txt` | SMTP sender email + app password |

These files live only on the device's flash storage — they are never part of this repo, and the included `.gitignore` blocks them if you ever try to add them.

`networks.txt` is backward-compatible with the older 2-field `ssid,pass` format — missing trailing fields default safely.

---

## Known Limitations

- Outage duration cannot be reconstructed exactly across a reboot (wall-clock snapshots only); if the device restarts mid-outage, the downtime counter restarts from boot.
- Single-radio ESP32 means AP+STA share one channel — the softAP is automatically started on the same channel as the target network to allow simultaneous operation.
- TLS certificate is self-signed, so all browsers will show a security warning on first connect.
- WiFi password storage on flash uses simple XOR obfuscation, not real encryption — sufficient to avoid plaintext-on-flash but not a substitute for physical device security.

---

## Version

**v7.4** — tolerant WiFi connect logic (full 30s poll window, no early bail-out), channel-matched softAP to fix AP+STA coexistence, SMTP credentials configurable from the dashboard (no reflash).
