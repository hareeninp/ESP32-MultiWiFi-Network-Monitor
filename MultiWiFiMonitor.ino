/*
 ================================================================
  Multi-WiFi Network Health Monitor
  Board   : ESP32 Dev Module
 ================================================================

  LIBRARIES (Sketch > Include Library > Manage Libraries):
  1. ReadyMail        by Mobizt
  2. ArduinoJson      by Benoit Blanchon
  3. PsychicHttp      by hoeken

  BOARD SETTINGS (Tools menu):
  - Board            : ESP32 Dev Module
  - Flash Size       : 4MB (FS: 2MB OTA ~1019KB)
  - Partition Scheme : Default 4MB with spiffs
  - Upload Speed     : 921600

  ZOHO MAIL SETUP:
  1. Sign in to Zoho Accounts (https://accounts.zoho.in)
  2. Go to Security > Application-Specific Passwords > Generate
  3. Copy the generated Application-Specific Password
  4. Enter sender email + that password in the dashboard
     under "SMTP Settings" — no reflashing needed!

  HTTPS:
  - Self-signed cert → browser will warn, click "Proceed"
 ================================================================
*/

// ── Core ─────────────────────────────────────────────────────
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <time.h>

// ── PsychicHttp HTTPS Server ──────────────────────────────────
#include <PsychicHttp.h>
#include <PsychicHttpsServer.h>

// ── ReadyMail ─────────────────────────────────────────────────
#define ENABLE_SMTP
#define ENABLE_DEBUG
#include <ReadyMail.h>

// ── JSON ──────────────────────────────────────────────────────
#include <ArduinoJson.h>

// ════════════════════════════════════════════════════════════
//  TLS CERTIFICATE AND PRIVATE KEY  (self-signed, 1 year)
// ════════════════════════════════════════════════════════════
const char* server_cert = R"EOF(-----BEGIN CERTIFICATE-----
// add yours 
-----END CERTIFICATE-----)EOF";

const char* server_key = R"EOF(-----BEGIN PRIVATE KEY-----
//add yours
-----END PRIVATE KEY-----)EOF";

// ════════════════════════════════════════════════════════════
//  USER CONFIGURATION  ← edit AP name/pass here if needed
// ════════════════════════════════════════════════════════════
#define AP_SSID        
#define AP_PASSWORD    

#define XOR_KEY        0x5A
#define MAX_NETWORKS   20
#define CYCLE_MS       300000UL   // 5 minutes

// ── WiFi connect tolerance ────────────────────────────────────
#define WIFI_CONNECT_TIMEOUT_MS  30000UL

// ── SMTP (fixed host/port — credentials set from dashboard) ──
#define SMTP_HOST      "smtp.zoho.in"
#define SMTP_PORT      465
#define SMTP_SENDER_NAME "WiFi Monitor"

// ── Alert recipient (fallback if not set in dashboard) ───────
#define ALERT_RECIPIENT   

// ── IFTTT (leave blank "" to disable) ────────────────────────
#define IFTTT_KEY            ""
#define IFTTT_ALERT_EVENT    "wifi_alert"
#define IFTTT_RECOVERY_EVENT "wifi_recovery"

// ── Internet probe endpoints ──────────────────────────────────
#define PROBE_PRIMARY   "http://clients3.google.com/generate_204"
#define PROBE_FALLBACK  "http://cp.cloudflare.com/generate_204"
#define PROBE_TERTIARY  "http://connectivitycheck.gstatic.com/generate_204"
#define PROBE_TIMEOUT   7000

// ── LittleFS files ────────────────────────────────────────────
#define NETWORKS_FILE  "/networks.txt"
#define EMAIL_FILE     "/email.txt"
#define AUTH_FILE      "/auth.txt"
#define SMTP_FILE      "/smtp.txt"   // line1=senderEmail  line2=appPassword

// ════════════════════════════════════════════════════════════
//  STATUS CONSTANTS
// ════════════════════════════════════════════════════════════
#define STATUS_PENDING          0
#define STATUS_HEALTHY          1
#define STATUS_NO_WIFI          2
#define STATUS_NO_INTERNET      3

// ════════════════════════════════════════════════════════════
//  DATA STRUCTURES
// ════════════════════════════════════════════════════════════
struct WiFiNetwork {
  char    ssid[33];
  char    encryptedPass[65];
  uint8_t status;             // current status (STATUS_*) == "currentStatus"
  bool    alertSent;          // an alert exists for the CURRENT outage episode
                               // (already emailed OR still queued) — blocks dupes
  bool    pendingAlert;       // true = alert generated but not yet emailed
  uint8_t alertRetryCount;    // monitoring cycles this alert has stayed queued
  char    lastChecked[16];    // HH:MM:SS of last monitoring pass ("" = never)
  char    lastHealthy[16];    // HH:MM:SS of last successful internet check
  char    lastFailure[16];    // HH:MM:SS of last failure detection
  char    lastRecovery[16];   // HH:MM:SS of last recovery
  unsigned long failStartMillis; // RAM-only: millis() when current outage began
                                  // (used for downtime calc — see v7.0 changelog)
  uint8_t consecutiveNoWifiCount;     // RAM-only: consecutive NO WIFI results in a row
  uint8_t consecutiveNoInternetCount; // RAM-only: consecutive NO INTERNET results in a row
                                       // (not persisted to LittleFS — same pattern as
                                       // failStartMillis; zeroed by memset on load/add)
};

// ════════════════════════════════════════════════════════════
//  GLOBALS
// ════════════════════════════════════════════════════════════
WiFiNetwork nets[MAX_NETWORKS];
int         netCount  = 0;

char alertEmail[64]   = "";
char smtpEmail[64]    = "";   // sender email  — set from dashboard
char smtpAppPass[64]  = "";   // app password  — set from dashboard
char dashUser[33]     = "admin";
char dashPass[65]     = "monitor123";
char sessionToken[33] = "";

PsychicHttpsServer server;
unsigned long lastCycleTime = 0;
bool          cycleRunning  = false;
bool          timeSynced    = false;

WiFiClientSecure smtpSSL;
SMTPClient       smtp(smtpSSL);

// ════════════════════════════════════════════════════════════
//  AP RESTART HELPER
// ════════════════════════════════════════════════════════════
void restartAP() {
  Serial.println(F("  [AP] Restarting Access Point..."));
  WiFi.disconnect(true, true);
  delay(300);
  WiFi.mode(WIFI_OFF);
  delay(500);
  WiFi.mode(WIFI_AP_STA);
  delay(500);
  WiFi.softAP(AP_SSID, AP_PASSWORD);
  delay(800);
  Serial.printf("  [AP] UP. IP: %s\n", WiFi.softAPIP().toString().c_str());
}

// ════════════════════════════════════════════════════════════
//  SESSION HELPERS
// ════════════════════════════════════════════════════════════
void generateToken() {
  const char* hex = "0123456789abcdef";
  for (int i = 0; i < 32; i++)
    sessionToken[i] = hex[esp_random() % 16];
  sessionToken[32] = '\0';
}
void clearToken() { memset(sessionToken, 0, sizeof(sessionToken)); }

bool isAuthenticated(PsychicRequest* req) {
  if (!sessionToken[0]) return false;
  String ch = req->header("Cookie");
  if (!ch.length()) return false;
  int idx = ch.indexOf("session=");
  if (idx < 0) return false;
  String tok = ch.substring(idx + 8);
  int end = tok.indexOf(';');
  if (end >= 0) tok = tok.substring(0, end);
  tok.trim();
  return tok.equals(String(sessionToken));
}

void redirectToLogin(PsychicResponse* res) {
  res->setCode(302);
  res->addHeader("Location", "/login");
  res->send("");
}

// ════════════════════════════════════════════════════════════
//  XOR ENCRYPTION (WiFi password obfuscation)
// ════════════════════════════════════════════════════════════
String encryptPassword(const char* plain) {
  String hex = "";
  for (int i = 0; plain[i]; i++) {
    uint8_t c = (uint8_t)plain[i] ^ XOR_KEY;
    if (c < 16) hex += "0";
    hex += String(c, HEX);
  }
  return hex;
}
String decryptPassword(const char* hexStr) {
  String plain = "";
  int len = strlen(hexStr);
  for (int i = 0; i + 1 < len; i += 2) {
    char b[3] = { hexStr[i], hexStr[i+1], '\0' };
    plain += (char)((uint8_t)strtol(b, NULL, 16) ^ XOR_KEY);
  }
  return plain;
}

// ════════════════════════════════════════════════════════════
//  WALL-CLOCK TIMESTAMP  (NTP-backed, with uptime fallback)
// ════════════════════════════════════════════════════════════
// Lazily syncs NTP the first time it's called while STA has a route to the
// internet. Safe to call repeatedly — it's a no-op once timeSynced is true.
void syncTimeIfNeeded() {
  if (timeSynced) return;
  if (WiFi.status() != WL_CONNECTED) return; // no STA link yet, don't block
  configTime(19800, 0, "pool.ntp.org", "time.google.com");
  unsigned long t0 = millis();
  while (time(nullptr) < 100000 && millis() - t0 < 5000) delay(100);
  if (time(nullptr) > 100000) {
    timeSynced = true;
    Serial.println(F("  [NTP] Time synced"));
  }
}

// Returns "HH:MM:SS" (real wall-clock time) once NTP has synced at least
// once; otherwise falls back to "~HH:MM:SS" uptime-since-boot so the field
// is never blank.
String getClockTimestamp() {
  syncTimeIfNeeded();
  char buf[16];
  if (timeSynced) {
    time_t now = time(nullptr);
    struct tm tmNow;
    localtime_r(&now, &tmNow);
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tmNow.tm_hour, tmNow.tm_min, tmNow.tm_sec);
  } else {
    unsigned long s = millis() / 1000;
    unsigned long m = s / 60; s %= 60;
    unsigned long h = m / 60; m %= 60;
    snprintf(buf, sizeof(buf), "~%02lu:%02lu:%02lu", h, m, s);
  }
  return String(buf);
}

// ════════════════════════════════════════════════════════════
//  STATUS LABEL
// ════════════════════════════════════════════════════════════
String statusLabel(uint8_t s) {
  switch (s) {
    case STATUS_HEALTHY:     return "HEALTHY";
    case STATUS_NO_WIFI:     return "NO WIFI";
    case STATUS_NO_INTERNET: return "NO INTERNET";
    default:                 return "PENDING";
  }
}

// ════════════════════════════════════════════════════════════
//  FILE SYSTEM HELPERS
// ════════════════════════════════════════════════════════════
// networks.txt line format (comma-separated, backward compatible with the
// old 2-field "ssid,pass" format — missing trailing fields default safely):
//   ssid,encryptedPass,status,alertSent,pendingAlert,retryCount,
//   lastChecked,lastHealthy,lastFailure,lastRecovery
void loadNetworks() {
  netCount = 0;
  if (!LittleFS.exists(NETWORKS_FILE)) return;
  File f = LittleFS.open(NETWORKS_FILE, "r");
  if (!f) return;
  while (f.available() && netCount < MAX_NETWORKS) {
    String line = f.readStringUntil('\n'); line.trim();
    if (!line.length()) continue;

    String parts[10];
    int nParts = 0, start = 0;
    while (nParts < 10) {
      int c = line.indexOf(',', start);
      if (c < 0) { parts[nParts++] = line.substring(start); break; }
      parts[nParts++] = line.substring(start, c);
      start = c + 1;
    }
    if (nParts < 2) continue; // need at least ssid + pass

    WiFiNetwork &n = nets[netCount];
    memset(&n, 0, sizeof(n));
    strncpy(n.ssid,          parts[0].c_str(), 32);
    strncpy(n.encryptedPass, parts[1].c_str(), 64);
    n.status          = (nParts > 2) ? (uint8_t)parts[2].toInt() : STATUS_PENDING;
    n.alertSent       = (nParts > 3) ? (parts[3].toInt() != 0)   : false;
    n.pendingAlert    = (nParts > 4) ? (parts[4].toInt() != 0)   : false;
    n.alertRetryCount = (nParts > 5) ? (uint8_t)parts[5].toInt() : 0;
    if (nParts > 6) strncpy(n.lastChecked,  parts[6].c_str(), 15);
    if (nParts > 7) strncpy(n.lastHealthy,  parts[7].c_str(), 15);
    if (nParts > 8) strncpy(n.lastFailure,  parts[8].c_str(), 15);
    if (nParts > 9) strncpy(n.lastRecovery, parts[9].c_str(), 15);
    // Outage duration can't be reconstructed across a reboot from wall-clock
    // snapshots alone — if we're loading a network that was mid-outage,
    // restart the downtime counter from now rather than reporting garbage.
    n.failStartMillis = (n.status != STATUS_HEALTHY && n.alertSent) ? millis() : 0;
    netCount++;
  }
  f.close();
  Serial.printf("[FS] Loaded %d network(s)\n", netCount);
}

void saveAllNetworks() {
  File f = LittleFS.open(NETWORKS_FILE, "w");
  if (!f) return;
  for (int i = 0; i < netCount; i++) {
    f.printf("%s,%s,%d,%d,%d,%d,%s,%s,%s,%s\n",
      nets[i].ssid, nets[i].encryptedPass,
      nets[i].status, nets[i].alertSent ? 1 : 0, nets[i].pendingAlert ? 1 : 0,
      nets[i].alertRetryCount,
      nets[i].lastChecked, nets[i].lastHealthy,
      nets[i].lastFailure, nets[i].lastRecovery);
  }
  f.close();
}

void deleteNetwork(int idx) {
  if (idx < 0 || idx >= netCount) return;
  for (int i = idx; i < netCount - 1; i++) nets[i] = nets[i+1];
  netCount--;
  saveAllNetworks();
}

void loadEmail() {
  if (!LittleFS.exists(EMAIL_FILE)) return;
  File f = LittleFS.open(EMAIL_FILE, "r");
  if (!f) return;
  String s = f.readStringUntil('\n'); s.trim();
  strncpy(alertEmail, s.c_str(), 63); alertEmail[63] = '\0';
  f.close();
}
void saveEmail() {
  File f = LittleFS.open(EMAIL_FILE, "w");
  if (!f) return;
  f.println(alertEmail); f.close();
}

// ── SMTP credentials file: line1=email  line2=apppass ────────
void loadSmtpCreds() {
  if (!LittleFS.exists(SMTP_FILE)) return;
  File f = LittleFS.open(SMTP_FILE, "r");
  if (!f) return;
  String em = f.readStringUntil('\n'); em.trim();
  String ap = f.readStringUntil('\n'); ap.trim();
  f.close();
  if (em.length()) { strncpy(smtpEmail,   em.c_str(), 63); smtpEmail[63]   = '\0'; }
  if (ap.length()) { strncpy(smtpAppPass, ap.c_str(), 63); smtpAppPass[63] = '\0'; }
}
void saveSmtpCreds() {
  File f = LittleFS.open(SMTP_FILE, "w");
  if (!f) return;
  f.println(smtpEmail);
  f.println(smtpAppPass);
  f.close();
}

void loadAuth() {
  if (!LittleFS.exists(AUTH_FILE)) return;
  File f = LittleFS.open(AUTH_FILE, "r");
  if (!f) return;
  String u = f.readStringUntil('\n'); u.trim();
  String p = f.readStringUntil('\n'); p.trim();
  f.close();
  if (u.length()) { strncpy(dashUser, u.c_str(), 32); dashUser[32] = '\0'; }
  if (p.length()) { strncpy(dashPass, p.c_str(), 64); dashPass[64] = '\0'; }
}
void saveAuth() {
  File f = LittleFS.open(AUTH_FILE, "w");
  if (!f) return;
  f.println(dashUser); f.println(dashPass); f.close();
}

// ════════════════════════════════════════════════════════════
//  connectToNetwork()  — full WiFi stack reset every time
// ════════════════════════════════════════════════════════════
// v7.1: Tolerant connection logic. Slow routers / slow DHCP can take well
// over the old 15s window to hand out an association + IP, which used to
// cause false STATUS_NO_WIFI results. This function now:
//   • Polls WiFi.status() continuously for the FULL WIFI_CONNECT_TIMEOUT_MS
//     (30s) window — it never gives up early just because a status code
//     looks discouraging mid-attempt (e.g. WL_IDLE_STATUS, WL_DISCONNECTED
//     while still associating). Only WL_CONNECTED (success) or the timeout
//     itself (failure) end the loop.
//   • Logs the current WiFi.status() code and elapsed seconds on every
//     poll so slow-but-eventually-successful connections are visible in
//     Serial rather than silently retried.
//   • Logs RSSI immediately once WL_CONNECTED is observed.
//   • Ends with one unambiguous "Final result" line either way.
// STATUS_NO_WIFI (assigned by the caller, monitorNetworks()) is only ever
// reached when this function returns false, i.e. after the entire 30s
// window has elapsed with no WL_CONNECTED.
bool connectToNetwork(const char* ssid, const char* pass) {
  Serial.println(F("  [WiFi] Full reset before connect..."));
  WiFi.disconnect(true, true);
  delay(300);
  WiFi.mode(WIFI_OFF);
  delay(500);
  WiFi.mode(WIFI_AP_STA);
  delay(500);

  // v7.2: Channel-matched softAP. The ESP32 has a single radio — in
  // AP+STA mode the STA can only associate with routers on the SAME
  // channel the softAP currently occupies. If the AP were brought up
  // first on a fixed default channel (1) and the target network happens
  // to be on a different channel, the STA connect attempt will sit at
  // WL_DISCONNECTED (status 6) forever no matter how long we wait — this
  // is what produced the "stuck at status 6 for the full 30s" symptom.
  // Fix: scan first, find the channel the target SSID is actually
  // broadcasting on, then start the softAP on that same channel so both
  // radios can coexist.
  Serial.printf("  [WiFi] Scanning to find channel for: %s\n", ssid);
  int foundChannel = 0; // 0 = not found in scan
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; i++) {
    if (WiFi.SSID(i).equals(ssid)) {
      foundChannel = WiFi.channel(i);
      Serial.printf("  [WiFi] Found '%s' on channel %d  (RSSI %d dBm)\n",
        ssid, foundChannel, WiFi.RSSI(i));
      break;
    }
  }
  WiFi.scanDelete();
  if (!foundChannel) {
    Serial.printf("  [WiFi] '%s' not seen in scan — starting AP on default channel 1\n", ssid);
    foundChannel = 1;
  }

  WiFi.softAP(AP_SSID, AP_PASSWORD, foundChannel);
  delay(500);
  WiFi.setAutoReconnect(false);
  WiFi.persistent(false);

  Serial.printf("  [WiFi] Connecting to: %s  (timeout: %lu s)\n",
    ssid, WIFI_CONNECT_TIMEOUT_MS / 1000UL);
  WiFi.begin(ssid, pass);

  unsigned long t0 = millis();
  unsigned long lastLog = 0;
  wl_status_t st = WiFi.status();

  // Keep polling for the ENTIRE timeout window — never bail out early on a
  // transient status code. Slow association / slow DHCP just means more
  // iterations of this loop, not a failure.
  while (st != WL_CONNECTED && (millis() - t0) < WIFI_CONNECT_TIMEOUT_MS) {
    delay(500);
    st = WiFi.status();
    unsigned long elapsedSec = (millis() - t0) / 1000UL;
    // Log roughly once per second rather than every 500ms poll
    if (elapsedSec != lastLog) {
      lastLog = elapsedSec;
      Serial.printf("  [WiFi] Status: %d  Elapsed: %lus / %lus\n",
        (int)st, elapsedSec, WIFI_CONNECT_TIMEOUT_MS / 1000UL);
    }
  }

  unsigned long totalElapsedSec = (millis() - t0) / 1000UL;

  if (st == WL_CONNECTED) {
    Serial.printf("  [WiFi] Connected after %lus. IP: %s  RSSI: %d dBm\n",
      totalElapsedSec, WiFi.localIP().toString().c_str(), WiFi.RSSI());
    Serial.println(F("  [WiFi] Final result: SUCCESS"));
    return true;
  }

  Serial.printf("  [WiFi] FAILED after full %lus timeout. Final status: %d\n",
    totalElapsedSec, (int)st);
  Serial.println(F("  [WiFi] Final result: NO WIFI"));
  return false;
}

// ════════════════════════════════════════════════════════════
//  checkInternet()  — triple-endpoint fallback
// ════════════════════════════════════════════════════════════
// v7.1: Logic unchanged from v6.5+ (already correct), documented and
// verified explicitly:
//   • Probes are tried in order: Google (primary) → Cloudflare → gstatic.
//   • The FIRST probe that returns HTTP 200 or 204 short-circuits the
//     function and returns true (HEALTHY) immediately — the remaining
//     probes are never even attempted in that case.
//   • STATUS_NO_INTERNET is only ever reported by the caller when this
//     function returns false, which only happens after ALL THREE probes
//     have been attempted and ALL THREE failed.
bool checkInternet() {
  struct Probe { const char* label; const char* url; };
  Probe probes[3] = {
    { "Google (primary)",  PROBE_PRIMARY  },
    { "Cloudflare",        PROBE_FALLBACK },
    { "Google (gstatic)",  PROBE_TERTIARY }
  };
  for (int i = 0; i < 3; i++) {
    Serial.printf("  [Internet] Checking %s...\n", probes[i].label);
    HTTPClient http;
    http.begin(probes[i].url);
    http.setTimeout(PROBE_TIMEOUT);
    int code = http.GET();
    http.end();
    Serial.printf("  [Internet] %s -> HTTP %d\n", probes[i].label, code);
    if (code == 204 || code == 200) {
      Serial.printf("  [Internet] %s succeeded -> HEALTHY (remaining probes skipped)\n",
        probes[i].label);
      return true;
    }
  }
  Serial.println(F("  [Internet] All 3 endpoints failed -> NO INTERNET"));
  return false;
}

// ════════════════════════════════════════════════════════════
//  EMAIL / IFTTT
// ════════════════════════════════════════════════════════════
void sendSMTPEmail(const String& subject, const String& body) {
  // Need both sender email and app password to be configured
  if (strlen(smtpEmail) < 5 || strlen(smtpAppPass) < 8) {
    Serial.println(F("[SMTP] Sender email or app password not configured — skipping email"));
    return;
  }
  String recipient = (strlen(alertEmail) > 3) ? String(alertEmail)
                                               : String(ALERT_RECIPIENT);
  if (recipient.length() < 5) return;

  smtpSSL.setInsecure();
  auto cb = [](SMTPStatus s){ Serial.println(s.text); };
  Serial.printf("[SMTP] Connecting to %s:%d...\n", SMTP_HOST, SMTP_PORT);
  smtp.connect(SMTP_HOST, SMTP_PORT, cb);
  if (!smtp.isConnected()) { Serial.println("[SMTP] Connect failed"); return; }
  smtp.authenticate(smtpEmail, smtpAppPass, readymail_auth_password);

  SMTPMessage msg;
  msg.headers.add(rfc822_from,
    String(SMTP_SENDER_NAME) + " <" + String(smtpEmail) + ">");
  msg.headers.add(rfc822_to,      recipient);
  msg.headers.add(rfc822_subject, subject);

  String html = "<html><body style='font-family:Arial,sans-serif;padding:20px'>";
  html += "<h2 style='color:#c0392b'>&#9888; WiFi Monitor Alert</h2>";
  html += "<pre style='background:#f4f4f4;padding:15px;border-radius:6px'>" + body + "</pre>";
  html += "<p style='color:#888;font-size:12px'>Sent by ESP32 WiFi Monitor</p></body></html>";

  msg.text.body(body);
  msg.html.body(html);

  syncTimeIfNeeded();
  if (timeSynced) msg.timestamp = time(nullptr);

  smtp.send(msg);
}

void sendIFTTT(const char* event,
               const String& v1, const String& v2, const String& v3) {
  if (strlen(IFTTT_KEY) < 5) return;
  String url = "http://maker.ifttt.com/trigger/";
  url += event; url += "/with/key/"; url += IFTTT_KEY;
  HTTPClient http; http.begin(url);
  http.addHeader("Content-Type", "application/json");
  String p = "{\"value1\":\"" + v1 + "\",\"value2\":\"" + v2 + "\",\"value3\":\"" + v3 + "\"}";
  http.POST(p); http.end();
}

// ── Send ONE recovery email for network idx. Must be called while STA is
//    still connected to that (now-healthy) network. ─────────────────────
void sendRecoveryEmailNow(int idx) {
  unsigned long downtimeMin = 0;
  if (nets[idx].failStartMillis > 0) {
    downtimeMin = (millis() - nets[idx].failStartMillis) / 60000UL;
  }
  String ts = getClockTimestamp();

  String subject = "WiFi Recovery: " + String(nets[idx].ssid) + " is back online";
  String body  = String(nets[idx].ssid) + "\n";
  body        += "Recovered\n\n";
  body        += "Recovery Time: " + ts + "\n";
  body        += "Downtime: " + String(downtimeMin) + " minute" + (downtimeMin == 1 ? "" : "s") + "\n";

  Serial.printf("  [Alert] Sending recovery email for %s (downtime ~%lu min)\n",
    nets[idx].ssid, downtimeMin);

  sendSMTPEmail(subject, body);
  sendIFTTT(IFTTT_RECOVERY_EVENT, subject, "Network: " + String(nets[idx].ssid), "Status: HEALTHY");

  strncpy(nets[idx].lastRecovery, ts.c_str(), 15); nets[idx].lastRecovery[15] = '\0';
}

// ── Flush every OTHER network's pendingAlert as one combined email, sent
//    through the network at throughIdx (which must be HEALTHY and the
//    currently-live STA connection). No-op if nothing is pending. ───────
void flushPendingAlerts(int throughIdx) {
  int pendingIdx[MAX_NETWORKS];
  int pendingN = 0;
  for (int j = 0; j < netCount; j++) {
    if (j == throughIdx) continue;
    if (nets[j].pendingAlert) pendingIdx[pendingN++] = j;
  }
  if (!pendingN) return;

  Serial.printf("  [Alert] Flushing %d queued alert(s) via %s\n",
    pendingN, nets[throughIdx].ssid);

  String subject = (pendingN == 1)
    ? ("WiFi Alert: " + String(nets[pendingIdx[0]].ssid))
    : "Multiple WiFi Alerts";

  String body = "";
  for (int k = 0; k < pendingN; k++) {
    int j = pendingIdx[k];
    body += String(nets[j].ssid) + "\n";
    body += statusLabel(nets[j].status) + "\n";
    body += "Detected: " + String(nets[j].lastFailure) + "\n\n";
  }
  body += "Alert sent through: " + String(nets[throughIdx].ssid) + "\n";
  body += "Timestamp: " + getClockTimestamp() + "\n";

  sendSMTPEmail(subject, body);
  sendIFTTT(IFTTT_ALERT_EVENT, subject,
    "via " + String(nets[throughIdx].ssid), getClockTimestamp());

  for (int k = 0; k < pendingN; k++) {
    nets[pendingIdx[k]].pendingAlert    = false;
    nets[pendingIdx[k]].alertRetryCount = 0;
    // alertSent stays true — the outage is still ongoing, this just marks
    // "already emailed" so we don't queue/send it again until it recovers.
  }
  saveAllNetworks();
}

// ════════════════════════════════════════════════════════════
//  MONITOR
// ════════════════════════════════════════════════════════════
void monitorNetworks() {
  if (!netCount) return;
  cycleRunning = true;
  WiFi.setAutoReconnect(false);
  WiFi.persistent(false);
  Serial.printf("\n=== Cycle Start [%s] ===\n", getClockTimestamp().c_str());

  for (int i = 0; i < netCount; i++) {
    Serial.printf("\n[%d/%d] Testing: %s\n", i+1, netCount, nets[i].ssid);
    uint8_t prevStatus = nets[i].status;
    uint8_t newStatus;
    String  plainPass  = decryptPassword(nets[i].encryptedPass);

    bool wifiOk = connectToNetwork(nets[i].ssid, plainPass.c_str());
    if (!wifiOk) {
      newStatus = STATUS_NO_WIFI;
      nets[i].consecutiveNoWifiCount++;
      nets[i].consecutiveNoInternetCount = 0;
    } else if (!checkInternet()) {
      newStatus = STATUS_NO_INTERNET;
      nets[i].consecutiveNoWifiCount = 0;
      nets[i].consecutiveNoInternetCount++;
    } else {
      newStatus = STATUS_HEALTHY;
      nets[i].consecutiveNoWifiCount = 0;
      nets[i].consecutiveNoInternetCount = 0;
    }

    String ts = getClockTimestamp();
    strncpy(nets[i].lastChecked, ts.c_str(), 15); nets[i].lastChecked[15] = '\0';

    if (newStatus == STATUS_HEALTHY) {
      strncpy(nets[i].lastHealthy, ts.c_str(), 15); nets[i].lastHealthy[15] = '\0';

      // ── Recovery: this network was down and had an alert outstanding ──
      if (prevStatus != STATUS_HEALTHY && nets[i].alertSent) {
        sendRecoveryEmailNow(i);
        nets[i].alertSent       = false;
        nets[i].pendingAlert    = false;
        nets[i].alertRetryCount = 0;
        nets[i].failStartMillis = 0;
      }

      nets[i].status = newStatus;
      Serial.println(F("  -> HEALTHY"));

      // ── While this live, healthy connection is up, flush anything
      //    queued from OTHER networks (never sent while a link was down) ──
      flushPendingAlerts(i);

    } else {
      nets[i].status = newStatus;
      strncpy(nets[i].lastFailure, ts.c_str(), 15); nets[i].lastFailure[15] = '\0';
      Serial.printf("  -> %s\n", statusLabel(newStatus).c_str());

      // ── Consecutive failure threshold: suppress alerts for transient
      //    (1-2 cycle) failures. Only queue an alert once the SAME failure
      //    type has occurred 3 cycles in a row. ─────────────────────────
      uint8_t consecCount = (newStatus == STATUS_NO_WIFI)
        ? nets[i].consecutiveNoWifiCount
        : nets[i].consecutiveNoInternetCount;
      Serial.printf("  [Threshold] Consecutive %s count: %d/3\n",
        statusLabel(newStatus).c_str(), consecCount);

      if (consecCount >= 3) {
        if (!nets[i].alertSent) {
          // New outage episode — queue it. Do NOT attempt SMTP on this
          // broken link; it'll be delivered via whichever network is next
          // found healthy (this cycle or a later one).
          nets[i].alertSent       = true;
          nets[i].pendingAlert    = true;
          nets[i].alertRetryCount = 0;
          nets[i].failStartMillis = millis();
          Serial.println(F("  [Alert] Queued (will send via next healthy network)"));
        } else if (nets[i].pendingAlert) {
          nets[i].alertRetryCount++;
          Serial.printf("  [Alert] Still pending delivery (retry #%d)\n", nets[i].alertRetryCount);
        }
      } else {
        Serial.println(F("  [Threshold] Below 3 consecutive failures — alert suppressed"));
      }
    }

    saveAllNetworks();
    WiFi.disconnect(true); delay(300);
  }

  // ── Post-pass: if a network tested HEALTHY earlier THIS cycle but other
  //    networks failed AFTER it (so nothing was pending yet when we flushed
  //    on the way past), reconnect to that known-good network once more to
  //    deliver the backlog before ending the cycle. ────────────────────
  for (int i = 0; i < netCount; i++) {
    if (nets[i].status != STATUS_HEALTHY) continue;

    bool anyPending = false;
    for (int j = 0; j < netCount; j++) {
      if (j != i && nets[j].pendingAlert) { anyPending = true; break; }
    }
    if (!anyPending) continue;

    Serial.printf("  [Alert] Reconnecting to known-healthy %s to flush backlog...\n",
      nets[i].ssid);
    String plainPass = decryptPassword(nets[i].encryptedPass);
    if (connectToNetwork(nets[i].ssid, plainPass.c_str())) {
      flushPendingAlerts(i);
      WiFi.disconnect(true); delay(300);
    } else {
      Serial.println(F("  [Alert] Reconnect failed — backlog stays queued for next cycle"));
    }
    break; // one healthy carrier per cycle is enough
  }

  restartAP();
  Serial.printf("=== Cycle Complete [%s] ===\n\n", getClockTimestamp().c_str());
  cycleRunning = false;
}

// ════════════════════════════════════════════════════════════
//  SHARED CSS VARIABLES (returned as a String)
// ════════════════════════════════════════════════════════════
// Common CSS snippet used by both login and dashboard
static const char COMMON_CSS[] PROGMEM =
  ":root{"
    "--bg:#080d18;--surf:#0e1625;--border:#162035;"
    "--green:#00ff88;--red:#ff3055;--yellow:#ffd000;"
    "--blue:#00d4ff;--text:#b8cce0;--dim:#3d5570"
  "}"
  "*{box-sizing:border-box;margin:0;padding:0}"
  "body{background:var(--bg);color:var(--text);"
       "font-family:'Segoe UI',Arial,Helvetica,sans-serif;"
       "min-height:100vh;padding:16px}"
  ".mono{font-family:Consolas,'Courier New',monospace}"
  "label{font-size:.62rem;letter-spacing:1px;text-transform:uppercase;"
        "color:var(--dim);display:block;margin-bottom:5px}"
  "input{background:var(--bg);border:1px solid var(--border);color:var(--text);"
        "padding:9px 12px;border-radius:6px;"
        "font-family:Consolas,'Courier New',monospace;"
        "font-size:.82rem;width:100%;outline:none;"
        "transition:border .2s,box-shadow .2s}"
  "input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(0,212,255,.08)}"
  ".inp-wrap{position:relative;display:flex;align-items:center}"
  ".inp-wrap input{padding-right:42px}"
  ".eye{"
    "position:absolute;right:10px;cursor:pointer;"
    "font-size:1.05rem;opacity:.4;"
    "user-select:none;transition:opacity .2s,color .2s;"
  "}"
  ".eye:hover{opacity:.9}"
  ".eye.on{opacity:1;color:var(--blue)}"
  ".btn{background:var(--blue);color:#000;border:none;"
       "padding:9px 20px;border-radius:6px;"
       "font-family:'Segoe UI',Arial,Helvetica,sans-serif;"
       "font-weight:700;font-size:.88rem;cursor:pointer;letter-spacing:1px}"
  ".btn:hover{opacity:.8}"
  ".btn:disabled{opacity:.4;cursor:not-allowed}"
  ".toast{padding:10px 14px;border-radius:6px;font-size:.82rem;"
         "margin-bottom:14px;border-left:3px solid;"
         "font-family:Consolas,'Courier New',monospace;display:none}"
  ".toast-ok{background:#002a15;border-color:var(--green);color:var(--green)}"
  ".toast-err{background:#2a0010;border-color:var(--red);color:var(--red)}"
  ".box{background:var(--surf);border:1px solid var(--border);"
       "border-radius:10px;padding:16px;margin-bottom:18px}"
  ".grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}"
  ".note{font-size:.68rem;color:var(--dim);margin-top:6px;"
        "font-family:Consolas,'Courier New',monospace}"
  ".hint{font-size:.66rem;color:var(--yellow);margin-top:5px;"
        "font-family:Consolas,'Courier New',monospace;"
        "padding:5px 8px;background:#1a1200;border-radius:4px;"
        "border-left:2px solid var(--yellow)}"
  "h2{font-size:.68rem;letter-spacing:3px;text-transform:uppercase;"
     "color:var(--dim);margin:18px 0 10px;"
     "display:flex;align-items:center;gap:8px}"
  "h2::before,h2::after{content:'';flex:1;height:1px;background:var(--border)}"
  "h2::after{flex:3}";

// ════════════════════════════════════════════════════════════
//  LOGIN PAGE
// ════════════════════════════════════════════════════════════
String buildLoginPage(bool badCreds = false) {
  String html = F("<!DOCTYPE html><html lang='en'><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>WiFi Monitor \xe2\x80\x94 Sign In</title>"
    "<style>");
  html += COMMON_CSS;
  html +=
    "body{display:flex;align-items:center;justify-content:center;"
         "background-image:"
           "radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.06) 0%,transparent 60%),"
           "radial-gradient(ellipse at 80% 20%,rgba(0,255,136,.04) 0%,transparent 50%);}"
    ".card{width:100%;max-width:400px;background:#0e1625;"
          "border:1px solid var(--border);border-radius:16px;"
          "padding:40px 36px 36px;box-shadow:0 24px 64px rgba(0,0,0,.5)}"
    ".icon{width:52px;height:52px;"
          "background:linear-gradient(135deg,#00d4ff22,#00ff8822);"
          "border:1px solid #00d4ff44;border-radius:14px;"
          "display:flex;align-items:center;justify-content:center;"
          "font-size:1.4rem;margin:0 auto 20px}"
    "h1{text-align:center;font-size:1.5rem;font-weight:700;"
       "letter-spacing:3px;text-transform:uppercase;color:#e8f4ff;margin-bottom:4px}"
    ".sub{text-align:center;font-size:.65rem;letter-spacing:2px;"
         "color:var(--dim);font-family:Consolas,'Courier New',monospace;margin-bottom:32px}"
    ".field{margin-bottom:18px}"
    "label{font-size:.6rem}"
    ".err{background:#2a0010;border:1px solid var(--red);color:var(--red);"
         "border-radius:8px;padding:10px 14px;font-size:.78rem;"
         "font-family:Consolas,'Courier New',monospace;"
         "margin-bottom:18px;display:flex;align-items:center;gap:8px}"
    ".btn{width:100%;background:linear-gradient(135deg,#00d4ff,#0099cc);"
         "padding:13px;border-radius:8px;font-size:1rem;"
         "letter-spacing:2px;text-transform:uppercase;margin-top:8px;"
         "transition:opacity .2s,transform .1s}"
    ".btn:active{transform:scale(.98)}"
    ".footer{text-align:center;margin-top:24px;font-size:.6rem;"
            "letter-spacing:1px;color:#1e2d42;"
            "font-family:Consolas,'Courier New',monospace}"
    "</style></head><body>"
    "<div class='card'>"
    "<div class='icon'>&#9650;</div>"
    "<h1>WiFi Monitor</h1>"
    "<div class='sub'>ESP32 &nbsp;&#183;&nbsp; HTTPS &nbsp;&#183;&nbsp; 192.168.4.1</div>";

  if (badCreds)
    html += "<div class='err'>&#10007;&nbsp; Invalid username or password</div>";

  html +=
    "<form method='POST' action='/login'>"
    "<div class='field'><label>Username</label>"
    "<input type='text' name='user' placeholder='Enter username' autocomplete='username' required autofocus></div>"
    "<div class='field'><label>Password</label>"
    "<input type='password' name='pass' placeholder='Enter password' autocomplete='current-password' required></div>"
    "<button class='btn' type='submit'>Sign In</button>"
    "</form>"
    "<div class='footer'>ESP32 &nbsp;|&nbsp; v7.4</div>"
    "</div></body></html>";

  return html;
}

// ════════════════════════════════════════════════════════════
//  DASHBOARD
// ════════════════════════════════════════════════════════════
String buildDashboard() {
  int total = netCount, healthy = 0, issues = 0, queued = 0;
  for (int i = 0; i < netCount; i++) {
    if      (nets[i].status == STATUS_HEALTHY) healthy++;
    else if (nets[i].status != STATUS_PENDING) issues++;
    if (nets[i].pendingAlert) queued++;
  }

  bool smtpReady = (strlen(smtpEmail) >= 5 && strlen(smtpAppPass) >= 8);
  bool iftttOk   = (strlen(IFTTT_KEY) > 5);

  String html = F("<!DOCTYPE html><html lang='en'><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>WiFi Monitor</title><style>");
  html += COMMON_CSS;
  html +=
    "header{display:flex;align-items:center;gap:12px;"
           "border-bottom:1px solid var(--border);"
           "padding-bottom:14px;margin-bottom:20px}"
    ".logo{font-size:1.4rem;font-weight:700;letter-spacing:3px;"
          "color:var(--blue);text-transform:uppercase}"
    ".sub{font-size:.7rem;letter-spacing:2px;color:var(--dim)}"
    ".dot{width:10px;height:10px;border-radius:50%;margin-left:auto;flex-shrink:0}"
    ".dot.ok{background:var(--green)}"
    ".dot.run{background:var(--yellow);animation:blink .6s infinite alternate}"
    "@keyframes blink{to{opacity:.2}}"
    ".logout-btn{font-size:.62rem;letter-spacing:1px;color:var(--dim);"
                "text-decoration:none;border:1px solid var(--border);"
                "padding:4px 10px;border-radius:4px;"
                "font-family:Consolas,'Courier New',monospace;"
                "transition:color .2s,border-color .2s}"
    ".logout-btn:hover{color:var(--red);border-color:var(--red)}"
    ".cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:22px}"
    ".card{background:var(--surf);border:1px solid var(--border);"
          "border-radius:10px;padding:14px;text-align:center}"
    ".card .n{font-size:2.2rem;font-weight:700}"
    ".card .l{font-size:.6rem;letter-spacing:2px;text-transform:uppercase;"
             "color:var(--dim);margin-top:3px}"
    ".ct .n{color:var(--blue)}.co .n{color:var(--green)}.cf .n{color:var(--red)}.cq .n{color:var(--yellow)}"
    ".tbl{width:100%;border-collapse:collapse;font-size:.82rem;margin-bottom:22px}"
    ".tbl th{background:var(--border);color:var(--dim);font-size:.6rem;"
            "letter-spacing:2px;text-transform:uppercase;padding:8px 10px;text-align:left}"
    ".tbl td{padding:9px 10px;border-bottom:1px solid var(--border)}"
    ".tbl tr:last-child td{border-bottom:none}"
    ".tbl tr:hover td{background:#0a1220}"
    ".badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:.65rem;"
           "font-weight:600;letter-spacing:1px;font-family:Consolas,'Courier New',monospace}"
    ".bh{background:#002d1a;color:var(--green);border:1px solid var(--green)}"
    ".br{background:#2d0010;color:var(--red);border:1px solid var(--red)}"
    ".bp{background:#001a2d;color:var(--blue);border:1px solid var(--blue)}"
    ".bni{background:#2d1a00;color:var(--yellow);border:1px solid var(--yellow)}"
    ".pend{display:inline-block;margin-left:6px;font-size:.6rem;color:var(--yellow);"
          "font-family:Consolas,'Courier New',monospace}"
    ".btn-del{background:transparent;color:var(--red);border:1px solid var(--red);"
             "padding:4px 10px;border-radius:4px;font-size:.7rem;cursor:pointer}"
    ".btn-del:hover{background:var(--red);color:#fff}"
    ".empty{color:var(--dim);font-size:.82rem;padding:16px 0;text-align:center}"
    ".ok-tag{color:var(--green)}.err-tag{color:var(--red)}"
    ".capacity{font-size:.65rem;color:var(--dim);margin-bottom:8px;"
              "font-family:Consolas,'Courier New',monospace}"
    ".capacity span{color:var(--blue)}"
    ".sched-note{font-size:.65rem;color:var(--dim);"
                "font-family:Consolas,'Courier New',monospace;"
                "margin-top:8px;padding:6px 10px;background:#0a1220;"
                "border-radius:4px;border-left:3px solid var(--blue)}"
    ".spin-msg{font-size:.75rem;color:var(--yellow);"
              "font-family:Consolas,'Courier New',monospace;"
              "margin-bottom:8px;padding:8px 12px;background:#1a1400;"
              "border-radius:4px;border-left:3px solid var(--yellow);display:none}"
    ".rfbar{font-size:.65rem;color:var(--dim);text-align:right;margin-top:18px}"
    "</style></head><body>";

  // ── Header ────────────────────────────────────────────────
  html += "<header><div>"
          "<div class='logo'>&#9650; WiFi Monitor</div>"
          "<div class='sub'>ESP32 &nbsp;|&nbsp; https://192.168.4.1 &nbsp;|&nbsp; v7.4</div>"
          "</div>";
  html += cycleRunning ? "<div class='dot run'></div>" : "<div class='dot ok'></div>";
  html += "<a class='logout-btn' href='/logout'>Sign Out</a></header>";

  // ── Summary cards ─────────────────────────────────────────
  html += "<div class='cards'>"
          "<div class='card ct'><div class='n'>" + String(total)   + "</div><div class='l'>Networks</div></div>"
          "<div class='card co'><div class='n'>" + String(healthy) + "</div><div class='l'>Healthy</div></div>"
          "<div class='card cf'><div class='n'>" + String(issues)  + "</div><div class='l'>Issues</div></div>"
          "<div class='card cq'><div class='n'>" + String(queued)  + "</div><div class='l'>Alerts Queued</div></div>"
          "</div>";

  // ── Network table ─────────────────────────────────────────
  html += "<h2>Monitored Networks</h2>";
  html += "<p class='capacity'>Capacity: <span>" + String(netCount) + " / " + String(MAX_NETWORKS) + "</span></p>";
  if (!netCount) {
    html += "<p class='empty'>No networks yet. Use the form below to add up to 20.</p>";
  } else {
    html += "<table class='tbl'><tr>"
            "<th>#</th><th>SSID</th><th>Status</th><th>Last Checked</th><th>Last Healthy</th><th>Del</th></tr>";
    for (int i = 0; i < netCount; i++) {
      String bc;
      if      (nets[i].status == STATUS_HEALTHY)     bc = "bh";
      else if (nets[i].status == STATUS_NO_INTERNET) bc = "bni";
      else if (nets[i].status == STATUS_NO_WIFI)     bc = "br";
      else                                            bc = "bp";

      String lastCheckedDisp = strlen(nets[i].lastChecked) ? String(nets[i].lastChecked) : "—";
      String lastHealthyDisp = strlen(nets[i].lastHealthy) ? String(nets[i].lastHealthy) : "Never";

      html += "<tr>"
              "<td class='mono'>" + String(i+1) + "</td>"
              "<td class='mono'><b>" + String(nets[i].ssid) + "</b></td>"
              "<td><span class='badge " + bc + "'>" + statusLabel(nets[i].status) + "</span>";
      if (nets[i].pendingAlert) html += "<span class='pend'>&#9203; queued</span>";
      html += "</td>"
              "<td class='mono' style='font-size:.7rem'>" + lastCheckedDisp + "</td>"
              "<td class='mono' style='font-size:.7rem'>" + lastHealthyDisp + "</td>"
              "<td><button class='btn-del' "
              "onclick=\"delNet(" + String(i) + ",'" + String(nets[i].ssid) + "')\">&#x2715;</button></td></tr>";
    }
    html += "</table>";
    html += "<p class='sched-note'>&#9201; Health check every <b style='color:var(--blue)'>5 min</b>. "
            "Alerts are only sent through a network that is currently HEALTHY — "
            "never over a broken link.</p>";
  }

  // ── Add Network ───────────────────────────────────────────
  html += "<h2>Add Network</h2><div class='box'>";
  if (netCount >= MAX_NETWORKS) {
    html += "<p class='empty'>&#9888; Maximum 20 networks reached. Delete one to add another.</p>";
  } else {
    html +=
      "<div id='addToast' class='toast'></div>"
      "<div id='addSpin' class='spin-msg'>&#9711; Connecting&hellip; please wait up to 30 seconds</div>"
      "<div class='grid2'>"
        // SSID
        "<div>"
          "<label>SSID &mdash; WiFi Network Name</label>"
          "<input type='text' id='fSSID' "
          "placeholder='Exact network name (case-sensitive)' "
          "maxlength='32' autocomplete='off' spellcheck='false'>"
          "<p class='note'>&#9432; Copy the exact SSID from your router or phone hotspot settings.</p>"
        "</div>"
        // Password with eye
        "<div>"
          "<label>WiFi Password</label>"
          "<div class='inp-wrap'>"
            "<input type='password' id='fPass' "
            "placeholder='Leave blank for open networks' "
            "maxlength='63' autocomplete='off'>"
            "<span class='eye' id='eyeWifi' onclick='toggleEye(\"fPass\",\"eyeWifi\")' "
            "title='Show / hide password'>&#128065;</span>"
          "</div>"
          "<p class='note'>&#9432; Spaces are allowed in WiFi passwords.</p>"
        "</div>"
      "</div>"
      "<br>"
      "<button class='btn' id='addBtn' onclick='doAdd()'>+ Add &amp; Verify Network</button>";
  }
  html += "</div>";

  // ── Alert Email ───────────────────────────────────────────
  html += "<h2>Alert Email Recipient</h2><div class='box'>"
          "<div id='emailToast' class='toast'></div>"
          "<label>Send alerts to this address</label>"
          "<input type='email' id='fEmail' placeholder='recipient@gmail.com' "
          "maxlength='63' value='" + String(alertEmail) + "'>"
          "<br><br>"
          "<button class='btn' onclick='doSaveEmail()'>&#128231; Save Recipient</button>"
          "</div>";

  // ── SMTP Settings (sender email + app password) ───────────
  // Mask stored app password: fully masked placeholder, no real
  // characters of the stored secret are ever sent to the browser.
  String maskedPass = "";
  if (strlen(smtpAppPass)) {
    maskedPass = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
  }

  html += "<h2>SMTP Settings</h2><div class='box'>"
          "<div id='smtpToast' class='toast'></div>"
          "<div class='grid2'>"
            "<div>"
              "<label>SMTP Sender Address</label>"
              "<input type='email' id='fSmtpEmail' "
              "placeholder='yourname@zoho.in' maxlength='63' "
              "value='" + String(smtpEmail) + "'>"
            "</div>"
            "<div>"
              "<label>SMTP App Password</label>"
              "<div class='inp-wrap'>"
                "<input type='password' id='fSmtpPass' "
                "placeholder='" + (strlen(smtpAppPass) ? maskedPass : "12-character Zoho App Password") + "' "
                "maxlength='64' autocomplete='off'>"
                "<span class='eye' id='eyeSmtp' onclick='toggleEye(\"fSmtpPass\",\"eyeSmtp\")' "
                "title='Show / hide app password'>&#128065;</span>"
              "</div>"
              "<p class='hint'>&#9888; Generate a Zoho Application-Specific Password under "
              "Zoho Accounts &rarr; Security &rarr; Application-Specific Passwords, then paste "
              "the 12-character code here WITHOUT spaces.</p>"
            "</div>"
          "</div>"
          "<p class='note' style='margin-top:10px'>"
          "SMTP server: <b style='color:var(--blue)'>" + String(SMTP_HOST) + "</b> &nbsp;|&nbsp; "
          "Port: <b style='color:var(--blue)'>" + String(SMTP_PORT) + " (SSL)</b> &nbsp;|&nbsp; "
          "Status: ";
  html += smtpReady
    ? "<span class='ok-tag'>&#10003; Configured</span>"
    : "<span class='err-tag'>&#10007; Not configured yet</span>";
  html +=
          "</p>"
          "<br>"
          "<button class='btn' onclick='doSaveSmtp()'>&#128274; Save SMTP Settings</button>"
          "</div>";

  // ── Alert System summary ──────────────────────────────────
  html += "<h2>Alert System</h2><div class='box'>";
  html += "<p style='font-size:.82rem'>SMTP: <b style='color:var(--blue)'>" + String(SMTP_HOST) + " — SSL port " + String(SMTP_PORT) + "</b></p>";
  html += "<p class='note'>Sender: ";
  html += smtpReady
    ? "<span class='ok-tag'>&#10003; " + String(smtpEmail) + "</span>"
    : "<span class='err-tag'>&#10007; Set sender email &amp; app password above</span>";
  html += "</p><p class='note'>Recipient: ";
  html += (strlen(alertEmail) > 3)
    ? "<span class='ok-tag'>&#10003; " + String(alertEmail) + "</span>"
    : "<span style='color:var(--dim)'>Using default: " + String(ALERT_RECIPIENT) + "</span>";
  html += "</p><p class='note'>IFTTT: ";
  html += iftttOk ? "<span class='ok-tag'>&#10003; Enabled</span>"
                  : "<span style='color:var(--dim)'>Disabled</span>";
  html += "</p><p class='note'>Delivery: <span style='color:var(--dim)'>Alerts are queued while every "
          "monitored network is down, and flushed automatically through the next network that "
          "comes back HEALTHY — nothing is lost.</span></p>";
  html += "</div>";

  // ── Change Login Credentials ──────────────────────────────
  html += "<h2>Change Login Credentials</h2><div class='box'>"
          "<div id='authToast' class='toast'></div>"
          "<div class='grid2'>"
          "<div><label>New Username</label>"
          "<input type='text' id='aUser' placeholder='1\xe2\x80\x9332 characters' maxlength='32'></div>"
          "<div><label>New Password</label>"
          "<input type='password' id='aPass' placeholder='Min 8 characters' maxlength='64'></div>"
          "</div><br>"
          "<div class='grid2'>"
          "<div><label>Confirm Password</label>"
          "<input type='password' id='aConf' placeholder='Repeat new password' maxlength='64'></div>"
          "<div style='display:flex;align-items:flex-end'>"
          "<button class='btn' style='width:100%' onclick='doSaveAuth()'>&#128274; Update Credentials</button>"
          "</div></div>"
          "<p class='note' style='margin-top:8px;color:var(--dim)'>"
          "&#9432; You will be signed out after saving.</p>"
          "</div>";

  html += "<div class='rfbar mono' id='rfBar'>Auto-refresh in <span id='rfCount'>30</span>s &nbsp;|&nbsp; v7.4</div>";

  // ── JavaScript ────────────────────────────────────────────
  html += R"JS(
<script>
// ── Auto-refresh (pauses while any input is focused) ─────────
var rfs = 30, rfp = false;
setInterval(function() {
  if (rfp) return;
  rfs--;
  var el = document.getElementById('rfCount');
  if (el) el.textContent = rfs;
  if (rfs <= 0) location.reload();
}, 1000);
document.addEventListener('focusin', function(e) {
  if (e.target.tagName === 'INPUT') {
    rfp = true;
    var b = document.getElementById('rfBar');
    if (b) b.textContent = 'Auto-refresh paused while typing\u2026';
  }
});
document.addEventListener('focusout', function(e) {
  if (e.target.tagName === 'INPUT') {
    rfp = false; rfs = 30;
    var b = document.getElementById('rfBar');
    if (b) b.innerHTML = 'Auto-refresh in <span id="rfCount">30</span>s &nbsp;|&nbsp; v7.4';
  }
});

// ── Generic eye toggle (works for any field pair) ─────────────
function toggleEye(inputId, btnId) {
  var inp = document.getElementById(inputId);
  var btn = document.getElementById(btnId);
  if (!inp || !btn) return;
  var show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  btn.classList.toggle('on', show);
  btn.title = show ? 'Hide' : 'Show';
  // Keep focus and move cursor to end
  inp.focus();
  var v = inp.value; inp.value = ''; inp.value = v;
}

// ── Toast helper ──────────────────────────────────────────────
function showToast(id, ok, msg) {
  var el = document.getElementById(id);
  if (!el) return;
  el.className = 'toast ' + (ok ? 'toast-ok' : 'toast-err');
  el.textContent = msg;
  el.style.display = 'block';
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── Delete network ────────────────────────────────────────────
function delNet(idx, ssid) {
  if (!confirm('Delete "' + ssid + '" from monitoring?')) return;
  window.location = '/delete?idx=' + idx;
}

// ── Add Network ───────────────────────────────────────────────
async function doAdd() {
  var ssidEl = document.getElementById('fSSID');
  var passEl = document.getElementById('fPass');
  var btn    = document.getElementById('addBtn');
  var spin   = document.getElementById('addSpin');
  var ssid   = ssidEl ? ssidEl.value.trim() : '';
  var pass   = passEl ? passEl.value : '';   // keep spaces

  if (!ssid) { showToast('addToast', false, '\u2716 SSID cannot be empty.'); return; }
  btn.disabled = true; btn.textContent = 'Verifying\u2026';
  if (spin) spin.style.display = 'block';
  document.getElementById('addToast').style.display = 'none';
  try {
    var fd = new FormData(); fd.append('ssid', ssid); fd.append('pass', pass);
    var r = await fetch('/add', { method: 'POST', body: fd });
    var j = await r.json();
    showToast('addToast', j.ok, j.message);
    if (j.ok) {
      ssidEl.value = ''; passEl.value = '';
      passEl.type = 'password';
      var eye = document.getElementById('eyeWifi');
      if (eye) { eye.classList.remove('on'); eye.title = 'Show / hide password'; }
      setTimeout(function() { location.reload(); }, 1800);
    }
  } catch(e) {
    showToast('addToast', false, '\u2716 Request failed: ' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = '+ Add & Verify Network';
    if (spin) spin.style.display = 'none';
  }
}

// ── Save Alert Email ──────────────────────────────────────────
async function doSaveEmail() {
  var em = document.getElementById('fEmail').value.trim();
  if (!em || em.indexOf('@') < 0) {
    showToast('emailToast', false, '\u2716 Enter a valid email address.'); return;
  }
  document.getElementById('emailToast').style.display = 'none';
  try {
    var fd = new FormData(); fd.append('email', em);
    var r  = await fetch('/saveemail', { method: 'POST', body: fd });
    var j  = await r.json();
    showToast('emailToast', j.ok, j.message);
  } catch(e) {
    showToast('emailToast', false, '\u2716 Request failed: ' + e.message);
  }
}

// ── Save SMTP Settings (email + app password) ─────────────────
async function doSaveSmtp() {
  var em = document.getElementById('fSmtpEmail').value.trim();
  var ap = document.getElementById('fSmtpPass').value.trim();
  // Remove any spaces the user accidentally left in app password
  ap = ap.replace(/\s/g, '');

  if (!em || em.indexOf('@') < 0) {
    showToast('smtpToast', false, '\u2716 Enter a valid SMTP sender address.'); return;
  }
  if (ap.length > 0 && ap.length !== 12) {
    showToast('smtpToast', false,
      '\u2716 App Password must be exactly 12 characters (got ' + ap.length + '). '
      + 'Remove spaces \u2014 Zoho shows it in groups but they are not part of the password.');
    return;
  }
  document.getElementById('smtpToast').style.display = 'none';
  try {
    var fd = new FormData();
    fd.append('smtpemail', em);
    fd.append('smtppass',  ap);
    var r = await fetch('/savesmtp', { method: 'POST', body: fd });
    var j = await r.json();
    showToast('smtpToast', j.ok, j.message);
    if (j.ok) setTimeout(function() { location.reload(); }, 1500);
  } catch(e) {
    showToast('smtpToast', false, '\u2716 Request failed: ' + e.message);
  }
}

// ── Save Login Credentials ────────────────────────────────────
async function doSaveAuth() {
  var u = document.getElementById('aUser').value.trim();
  var p = document.getElementById('aPass').value;
  var c = document.getElementById('aConf').value;
  if (u.length < 1 || u.length > 32) {
    showToast('authToast', false, '\u2716 Username must be 1\u201332 characters.'); return;
  }
  if (p.length < 8) {
    showToast('authToast', false, '\u2716 Password must be at least 8 characters.'); return;
  }
  if (p !== c) {
    showToast('authToast', false, '\u2716 Passwords do not match.'); return;
  }
  document.getElementById('authToast').style.display = 'none';
  try {
    var fd = new FormData();
    fd.append('newuser', u); fd.append('newpass', p); fd.append('confirmpass', c);
    var r = await fetch('/saveauth', { method: 'POST', body: fd });
    var j = await r.json();
    showToast('authToast', j.ok, j.message);
    if (j.ok) setTimeout(function() { window.location.href = '/logout'; }, 1800);
  } catch(e) {
    showToast('authToast', false, '\u2716 Request failed: ' + e.message);
  }
}
</script>
)JS";

  html += "</body></html>";
  return html;
}

// ════════════════════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════════════════════
void registerRoutes() {

  server.on("/login", HTTP_GET,
    [](PsychicRequest* req, PsychicResponse* res) {
      if (isAuthenticated(req)) { res->redirect("/"); return ESP_OK; }
      res->setCode(200); res->setContentType("text/html");
      res->send(buildLoginPage(false).c_str());
      return ESP_OK;
    });

  server.on("/login", HTTP_POST,
    [](PsychicRequest* req, PsychicResponse* res) {
      String user = req->hasParam("user") ? req->getParam("user")->value() : "";
      String pass = req->hasParam("pass") ? req->getParam("pass")->value() : "";
      user.trim();
      if (user.equals(String(dashUser)) && pass.equals(String(dashPass))) {
        generateToken();
        // Build the cookie into a named String first — inlining the
        // concatenation directly into addHeader() fails to compile because
        // a StringSumHelper temporary doesn't convert to const char*.
        String cookie = "session=" + String(sessionToken) + "; HttpOnly; Path=/; SameSite=Strict";
        res->setCode(302);
        res->addHeader("Set-Cookie", cookie.c_str());
        res->addHeader("Location", "/");
        res->send("");
      } else {
        res->setCode(200); res->setContentType("text/html");
        res->send(buildLoginPage(true).c_str());
      }
      return ESP_OK;
    });

  server.on("/logout", HTTP_GET,
    [](PsychicRequest* req, PsychicResponse* res) {
      clearToken();
      res->setCode(302);
      res->addHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0");
      res->addHeader("Location", "/login");
      res->send("");
      return ESP_OK;
    });

  server.on("/", HTTP_GET,
    [](PsychicRequest* req, PsychicResponse* res) {
      if (!isAuthenticated(req)) { redirectToLogin(res); return ESP_OK; }
      res->setCode(200); res->setContentType("text/html");
      res->send(buildDashboard().c_str());
      return ESP_OK;
    });

  // ── POST /add ─────────────────────────────────────────────
  server.on("/add", HTTP_POST,
    [](PsychicRequest* req, PsychicResponse* res) {
      res->setContentType("application/json");
      if (!isAuthenticated(req)) {
        res->setCode(401);
        res->send("{\"ok\":false,\"message\":\"Not authenticated.\"}");
        return ESP_OK;
      }
      if (!req->hasParam("ssid")) {
        res->setCode(400);
        res->send("{\"ok\":false,\"message\":\"Missing SSID field.\"}");
        return ESP_OK;
      }
      String ssid = req->getParam("ssid")->value(); ssid.trim();
      String pass = req->hasParam("pass") ? req->getParam("pass")->value() : String("");

      Serial.printf("\n[ADD] SSID='%s'  PassLen=%d\n", ssid.c_str(), pass.length());

      if (!ssid.length()) {
        res->send("{\"ok\":false,\"message\":\"SSID cannot be empty.\"}");
        return ESP_OK;
      }
      if (netCount >= MAX_NETWORKS) {
        res->send("{\"ok\":false,\"message\":\"Maximum 20 networks reached. Delete one first.\"}");
        return ESP_OK;
      }
      for (int i = 0; i < netCount; i++) {
        if (ssid.equalsIgnoreCase(nets[i].ssid)) {
          res->send(("{\"ok\":false,\"message\":\"\\u26A0 \\\"" + ssid + "\\\" already exists.\"}").c_str());
          return ESP_OK;
        }
      }

      WiFi.setAutoReconnect(false);
      WiFi.persistent(false);
      bool connected = connectToNetwork(ssid.c_str(), pass.c_str());
      Serial.printf("[ADD] Result: %s\n", connected ? "SUCCESS" : "FAILED");
      restartAP();

      if (!connected) {
        res->send(("{\"ok\":false,\"message\":\"\\u274C Cannot connect to \\\"" + ssid +
                   "\\\". Check SSID and password and try again.\"}").c_str());
        return ESP_OK;
      }

      WiFiNetwork &n = nets[netCount];
      memset(&n, 0, sizeof(n));
      strncpy(n.ssid,          ssid.c_str(), 32); n.ssid[32] = '\0';
      strncpy(n.encryptedPass, encryptPassword(pass.c_str()).c_str(), 64);
      n.encryptedPass[64] = '\0';
      n.status = STATUS_PENDING;
      netCount++;
      saveAllNetworks();
      Serial.printf("[ADD] Saved. Total: %d\n", netCount);

      res->send(("{\"ok\":true,\"message\":\"\\u2705 \\\"" + ssid +
                 "\\\" added and verified. (" + String(netCount) + "/" +
                 String(MAX_NETWORKS) + " networks)\"}").c_str());
      return ESP_OK;
    });

  server.on("/delete", HTTP_GET,
    [](PsychicRequest* req, PsychicResponse* res) {
      if (!isAuthenticated(req)) { redirectToLogin(res); return ESP_OK; }
      if (req->hasParam("idx")) {
        int idx = req->getParam("idx")->value().toInt();
        if (idx >= 0 && idx < netCount) deleteNetwork(idx);
      }
      res->redirect("/");
      return ESP_OK;
    });

  server.on("/saveemail", HTTP_POST,
    [](PsychicRequest* req, PsychicResponse* res) {
      res->setContentType("application/json");
      if (!isAuthenticated(req)) {
        res->setCode(401);
        res->send("{\"ok\":false,\"message\":\"Not authenticated.\"}");
        return ESP_OK;
      }
      if (!req->hasParam("email")) {
        res->send("{\"ok\":false,\"message\":\"Missing email field.\"}"); return ESP_OK;
      }
      String em = req->getParam("email")->value(); em.trim();
      if (em.length() < 5 || em.indexOf('@') < 0) {
        res->send("{\"ok\":false,\"message\":\"Enter a valid email address.\"}"); return ESP_OK;
      }
      strncpy(alertEmail, em.c_str(), 63); alertEmail[63] = '\0';
      saveEmail();
      res->send(("{\"ok\":true,\"message\":\"\\u2705 Recipient saved: " + em + "\"}").c_str());
      return ESP_OK;
    });

  // ── POST /savesmtp  (sender email + app password) ─────────
  server.on("/savesmtp", HTTP_POST,
    [](PsychicRequest* req, PsychicResponse* res) {
      res->setContentType("application/json");
      if (!isAuthenticated(req)) {
        res->setCode(401);
        res->send("{\"ok\":false,\"message\":\"Not authenticated.\"}");
        return ESP_OK;
      }

      String em = req->hasParam("smtpemail") ? req->getParam("smtpemail")->value() : "";
      String ap = req->hasParam("smtppass")  ? req->getParam("smtppass")->value()  : "";
      em.trim();
      // Strip any spaces from app password (user may have pasted with spaces)
      ap.replace(" ", "");
      ap.replace("\t", "");

      if (em.length() < 5 || em.indexOf('@') < 0) {
        res->send("{\"ok\":false,\"message\":\"Enter a valid SMTP sender address.\"}");
        return ESP_OK;
      }
      // App password may be left blank if only updating email
      if (ap.length() > 0 && ap.length() != 12) {
        String m = "{\"ok\":false,\"message\":\"App Password must be exactly 12 characters (got " +
                   String(ap.length()) + "). Remove all spaces.\"}";
        res->send(m.c_str()); return ESP_OK;
      }

      strncpy(smtpEmail, em.c_str(), 63); smtpEmail[63] = '\0';
      if (ap.length() == 12) {
        strncpy(smtpAppPass, ap.c_str(), 63); smtpAppPass[63] = '\0';
      }
      saveSmtpCreds();
      Serial.printf("[SMTP] Email: %s  Pass updated: %s\n",
        smtpEmail, ap.length() == 12 ? "yes" : "no (kept old)");

      String msg = "{\"ok\":true,\"message\":\"\\u2705 SMTP settings saved.";
      if (ap.length() == 0)
        msg += " (App password unchanged — leave blank to keep existing.)";
      msg += "\"}";
      res->send(msg.c_str());
      return ESP_OK;
    });

  server.on("/saveauth", HTTP_POST,
    [](PsychicRequest* req, PsychicResponse* res) {
      res->setContentType("application/json");
      if (!isAuthenticated(req)) {
        res->setCode(401);
        res->send("{\"ok\":false,\"message\":\"Not authenticated.\"}");
        return ESP_OK;
      }
      String newUser  = req->hasParam("newuser")     ? req->getParam("newuser")->value()     : "";
      String newPass  = req->hasParam("newpass")     ? req->getParam("newpass")->value()     : "";
      String confPass = req->hasParam("confirmpass") ? req->getParam("confirmpass")->value() : "";
      newUser.trim();
      if (newUser.length() < 1 || newUser.length() > 32) {
        res->send("{\"ok\":false,\"message\":\"Username must be 1\\u201332 characters.\"}"); return ESP_OK;
      }
      if (newPass.length() < 8 || newPass.length() > 64) {
        res->send("{\"ok\":false,\"message\":\"Password must be 8\\u201364 characters.\"}"); return ESP_OK;
      }
      if (newPass != confPass) {
        res->send("{\"ok\":false,\"message\":\"Passwords do not match.\"}"); return ESP_OK;
      }
      strncpy(dashUser, newUser.c_str(), 32); dashUser[32] = '\0';
      strncpy(dashPass, newPass.c_str(), 64); dashPass[64] = '\0';
      saveAuth(); clearToken();
      res->send("{\"ok\":true,\"message\":\"\\u2705 Credentials updated. Signing you out\\u2026\"}");
      return ESP_OK;
    });

  server.onNotFound(
    [](PsychicRequest* req, PsychicResponse* res) {
      res->redirect("/"); return ESP_OK;
    });
}

// ════════════════════════════════════════════════════════════
//  setup()
// ════════════════════════════════════════════════════════════
void setup() {
  Serial.begin(115200);
  delay(600);
  Serial.println(F("\n=== WiFi Health Monitor v7.4 — ESP32 ==="));

  WiFi.setAutoReconnect(false);
  WiFi.persistent(false);
  WiFi.mode(WIFI_OFF);
  delay(300);

  if (!LittleFS.begin(true)) {
    Serial.println(F("[FS] Formatting..."));
    LittleFS.format(); LittleFS.begin(true);
  }
  Serial.println(F("[FS] Mounted"));

  loadNetworks();
  loadEmail();
  loadAuth();
  loadSmtpCreds();

  Serial.printf("[Auth]  User     : %s\n", dashUser);
  Serial.printf("[SMTP]  Host     : %s:%d\n", SMTP_HOST, SMTP_PORT);
  Serial.printf("[SMTP]  Sender   : %s\n", strlen(smtpEmail) ? smtpEmail : "(not set)");
  Serial.printf("[SMTP]  AppPass  : %s\n", strlen(smtpAppPass) ? "****" : "(not set)");
  int pendingAtBoot = 0;
  for (int i = 0; i < netCount; i++) if (nets[i].pendingAlert) pendingAtBoot++;
  if (pendingAtBoot)
    Serial.printf("[Alert] %d alert(s) restored from LittleFS, still pending delivery\n", pendingAtBoot);

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASSWORD);
  delay(500);
  Serial.printf("[WiFi]  Hotspot  : '%s'  IP: %s\n",
    AP_SSID, WiFi.softAPIP().toString().c_str());

  server.setCertificate(server_cert, server_key);
  registerRoutes();
  server.begin();
  Serial.println(F("[Server] HTTPS running"));
  Serial.println(F("[Login]  https://192.168.4.1/login"));
  Serial.println(F("         Accept the certificate warning → click Proceed"));
}

// ════════════════════════════════════════════════════════════
//  loop()
// ════════════════════════════════════════════════════════════
void loop() {
  unsigned long now = millis();
  if (lastCycleTime == 0 || (now - lastCycleTime >= CYCLE_MS)) {
    lastCycleTime = now;
    monitorNetworks();
  }
}
