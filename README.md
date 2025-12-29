![Python](https://img.shields.io/badge/python-3.12+-blue.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue.svg)
![Security](https://img.shields.io/badge/security-defense-critical)
![Status](https://img.shields.io/badge/status-active-success.svg)
# TrafficSentinel

TrafficSentinel is a **lightweight, log-based web traffic detection engine** designed to analyze structured access logs (JSONL) from web servers such as **Nginx**.

It detects malicious and abusive HTTP traffic using **deterministic, rule-based logic**, assigns per-IP scores, and emits structured security events suitable for alerting, analysis, or downstream automation.

TrafficSentinel focuses on **visibility, explainability, and low resource usage**, rather than opaque ML models or inline request blocking.

> **Current status**
>
> - TrafficSentinel operates in **log ingestion mode only**
> - PCAP capture code exists but is **not wired into the runtime**
> - No automatic firewall enforcement is performed

---

## 1. Description

TrafficSentinel continuously monitors HTTP request logs and identifies suspicious behavior such as:

- Scanning and enumeration
- Exploit probing
- PHP-specific attack patterns
- Webshell discovery attempts
- Login bruteforce activity

Each detection contributes to a **per-IP score**, allowing operators to identify persistent or high-risk actors over time.

TrafficSentinel does **not** block traffic by itself.  
It is designed to integrate cleanly with tools like **Fail2Ban, SIEMs, alerting systems, or custom automation**.

---

## 2. Core Capabilities

- 📄 JSONL log ingestion (Nginx / reverse proxies)
- 🧠 Explainable rule-based detection
- 🔍 Detection categories:
  - Scan / enumeration
  - PHP exploit probes
  - Webshell paths
  - Suspicious automated requests
- 🔐 Log-based bruteforce detection
- 📊 Per-IP scoring and categorization
- 🧾 Append-only event logging
- 📬 Optional Telegram notifications
- 🐳 Docker-friendly
- ⚡ Low CPU and memory footprint

---

## 3. Operating Modes

### Log Ingestion Mode (Primary & Only Active Mode)

TrafficSentinel tails a newline-delimited JSON log file (`.jsonl`) and processes requests in near-real-time.

This mode:
- Works with HTTPS traffic
- Supports full application-layer visibility
- Is the **recommended and only supported production mode**

### PCAP Mode (Disabled / Experimental)

PCAP capture and analysis code exists in the repository but is **not connected to the runtime loop**.

- No live packet capture occurs
- No PCAPs are processed
- Included for potential future development only

---

## 4. Detection Engine

### Rules System

- Regex-based detection rules
- Rules are grouped by category (scan, php, exploit, etc.)
- **Only one best rule hit per request**
- Prevents score inflation from multiple matches

Rules are lightweight and curated for **practical, high-signal attack patterns**.

> TrafficSentinel does **not** currently use OWASP CRS compiled rules.

---

## 5. Reputation & Enforcement

### Reputation Model

- Reputation is calculated **in memory**
- Scores accumulate per IP
- No long-term persistence or decay
- No automatic banning or firewall changes

### Enforcement

TrafficSentinel performs **no direct enforcement**.

Instead, it provides:
- Structured events
- Clear scoring
- Reliable input for external tools

This design keeps TrafficSentinel:
- Safe to deploy
- Predictable
- Easy to integrate

---

## 6. Architecture Overview

```bash
        ┌────────────────────┐
        │  Nginx / Proxy     │
        │ (JSONL Access Log) │
        └─────────┬──────────┘
                  │
                  ▼
        ┌────────────────────┐
        │  TrafficSentinel   │
        └─────────┬──────────┘
                  │
    ┌─────────────▼─────────────┐
    │        Log Tailer          │
    │   (file tail / polling)   │
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │        JSON Parser         │
    │   (normalize requests)    │
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │        Rule Matcher        │
    │   (regex detection)       │
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │    Bruteforce Analyzer     │
    │ (rate & status analysis)  │
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │      Score Aggregator      │
    │     (per-IP scoring)      │
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │        Event Writer        │
    │     (state/events.log)    │
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │   Alert Dispatcher        │
    │     (Telegram optional)  │
    └───────────────────────────┘
 ```

---

## 7. Architecture Diagram (SVG)

![Architecture](docs/architecture.svg)

---

## 8. Project Structure

```
Traffic-Sentinel/
├── agent/ # PCAP capture code (inactive)
├── analyzer/ # Rule matching & scoring
├── ingestor/ # Log parsing & bruteforce detection
├── rules/ # Detection rules
├── config/ # Configuration files
├── state/ # Runtime state & event logs
├── cli.py # CLI entrypoint
└── main.py # Main runtime loop
```

---

## 9. Security Model & Limitations

### What TrafficSentinel Does Well

- Detects real application-layer attacks
- Handles HTTPS correctly via logs
- Produces explainable, auditable results
- Minimal performance impact

### Known Limitations

- No automatic blocking
- No HTTPS decryption in PCAP mode
- No clustering or distributed state
- No anomaly-based or ML detection
- Single-host scope

TrafficSentinel is **not a WAF replacement**.

---

## 10. Deployment

### Docker (Recommended)

```
docker compose up -d
or, docker-compose up -d
```

### Docker (Recommended)

```yaml
version: "3.8"

services:
  traffic-sentinel:
    image: python:3.11-slim
    container_name: traffic-sentinel
    working_dir: /app
    volumes:
      - ./Traffic-Sentinel:/app
      - /var/log/nginx:/hostlogs:ro
    command: ["python3", "cli.py", "run", "--interval", "2"]
    restart: unless-stopped
```

update config.yml:
```
log_path: "/hostlogs/trafficsentinel.jsonl"
```

### Authoritative Rule Files

- `config/rules_custom.yml` — user-defined rules

---

## 11. Log Ingestion (Primary & Only Active Mode)

### TrafficSentinel expects newline-delimited JSON logs.
Minimal Required Fields
```json
{
  "remote_addr": "1.2.3.4",
  "request": "GET /wp-login.php HTTP/1.1",
  "uri": "/wp-login.php",
  "status": 404,
  "ua": "Mozilla/5.0"
}
```
Recommended Fields
- xff
- method
- args
- ref
- body

---

## 12. Real Client IP (Cloudflare / Proxies)

TrafficSentinel does not infer real client IPs automatically.
Recommended: Nginx Real IP

```bash
real_ip_header CF-Connecting-IP;
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
real_ip_recursive on;
```
**Log $remote_addr after real IP processing.**

---

## 13. Nginx JSONL Logging (Example)
Request Body Capture (NJS)
`/etc/nginx/ts_body.js` :
```
function body(r) {
  var b = r.requestText || "";
  if (b.length > 2048) b = b.slice(0, 2048);
  return b;
}
export default { body };
```

**Nginx Configuration**
```bash
js_import ts from /etc/nginx/ts_body.js;
js_set $ts_body ts.body;

log_format ts_json escape=json
  '{"ts":"$time_iso8601",'
  '"remote_addr":"$remote_addr",'
  '"xff":"$http_x_forwarded_for",'
  '"request":"$request",'
  '"method":"$request_method",'
  '"uri":"$uri",'
  '"args":"$args",'
  '"status":$status,'
  '"ua":"$http_user_agent",'
  '"body":"$ts_body"'
  '}';

access_log /var/log/nginx/trafficsentinel.jsonl ts_json;
```

---

## 14. Bruteforce Detection (Log Mode)

Bruteforce detection works by:
- Monitoring authentication endpoints
- Counting failed responses (401 / 403)
- Grouping by IP per minute
- Emitting events when thresholds are exceeded

Example Configuration
```
ingestion:
  bruteforce:
    enabled: true
    endpoints:
      - /wp-login.php
      - /login
    threshold_per_minute: 10
    fail_statuses: [401, 403]
```
---

## 15. 🧾 Event Output

Events are written to:
```
state/events.log
```
Format:
```
timestamp ip=<IP> score=<score> cats=<categories> hits=<count> ua_only=<0|1>
```
This output is suitable for:

- Fail2Ban
- SIEM ingestion
- Alerting pipelines
- Custom scripts

### Scoring Model

- **Per-request scoring**
  - Each request contributes **at most +1 penalty**
  - Prevents score inflation from multi-pattern matches
- Penalties accumulate across multiple malicious requests

---

## Telegram Alerts
Telegram alerts are optional and disabled by default.

```
telegram:
  enabled: true
  bot_token: "${TELEGRAM_BOT_TOKEN}"
  chat_id: "${TELEGRAM_CHAT_ID}"
```

---

## Reputation & Enforcement

### Reputation State

Stored in `state/reputation.json`, tracking per IP:

- `penalty`
- `last_seen`
- `ban_until`
- `ban_count`
- `permanent`

---

### Penalty & Ban Logic

- Penalties decay after inactivity
- Temporary ban when penalty exceeds threshold
- Permanent ban after repeated temporary bans
- Allowlisted IPs are **never penalized**

---

### Firewall Enforcement

- Uses **iptables**
- Dedicated chain: `TS_BLOCK`
- Automatically:
  - Applies bans
  - Removes expired bans
  - Prevents duplicate firewall rules

## Logging

TrafficSentinel produces the following logs:

- **`state/events.log`**
  - Detection events
  - IP, score, hit count, categories

- **`state/actions.log`**
  - Ban events (with reasons)
  - Unban events (expired)
  - Permanent bans

- **`state/error.log`**
  - Capture, parsing, or enforcement errors

Logs are append-only and suitable for log rotation.

---

## Runtimr Setup
### Create the JSONL file on host:
```bash
sudo touch /var/log/nginx/trafficsentinel.jsonl
sudo chmod 644 /var/log/nginx/trafficsentinel.jsonl
```

### Systemd (Optional for automatic run):

do this:
```
sudo nano /etc/systemd/system/trafficsentinel.service
```
here do this:
```
[Unit]
Description=TrafficSentinel Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/Traffic-Sentinel
ExecStart=/usr/bin/python3 /root/Traffic-Sentinel/cli.py run
Restart=always
RestartSec=2
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```
then
```
sudo systemctl daemon-reload
sudo systemctl enable trafficsentinel
sudo systemctl start trafficsentinel
```
verify
```
sudo systemctl status trafficsentinel
```

---

## Admin CLI

TrafficSentinel provides a built-in CLI for manual administration:

```
python3 cli.py status
python3 cli.py top --n 20
python3 cli.py run
python3 cli.py show <IP>
python3 cli.py penalty-clear <IP>
python3 cli.py clear --yes
python3 cli.py ban <IP> --permanent| --seconds 2400
python3 cli.py unban <IP>
python3 cli.py tail|actions|error --lines 100
python3 cli.py allowlist list|add|remove
```

Used for inspection, overrides, and maintenance.

---

