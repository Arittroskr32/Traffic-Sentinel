# TrafficSentinel – How the Project Works (Simple Explanation)

TrafficSentinel is a **network traffic monitoring and auto-ban system**.
Its goal is to **detect malicious behavior** (SQLi, XSS, RCE, brute-force, scans)
and **automatically block attacker IPs** using firewall rules.

It works in **two modes**:

1. **PCAP Mode** → Network-level capture (HTTP only)
2. **Log Mode (Recommended)** → Application-level logs (HTTP + HTTPS)

---

## 1. High-Level Flow

```bash
[Traffic Source]
        ↓
[ Capture / Logs ]
        ↓
[ Parsing & Normalization ]
        ↓
[ Detection Engine ]
        ↓
[ Scoring & State Tracking ]
        ↓
[ Firewall Enforcement ]
```

---

## 2. How Traffic Is Collected

### 2.1 PCAP Mode (Network Capture)

**Files involved**

- `agent/capture.py`
- `analyzer/analyze.py`

**What happens**

- The system runs `tcpdump` to capture short PCAP slices
- `tshark` extracts **plaintext HTTP requests**
- Extracted data:
  - Source IP
  - URI / path / query
  - Headers (host, user-agent, cookie)
  - Body (if visible)

**Important**

- ❌ HTTPS payloads are **encrypted**
- ✅ Only **metadata** (IP behavior, SYN floods, scans) works for HTTPS here

So PCAP mode is:

- Good for **raw HTTP**
- Good for **network attacks**
- ❌ Not good for HTTPS content inspection

---

### 2.2 Log Mode (HTTPS-friendly)

**Files involved**

- `ingestor/log_reader.py`
- `ingestor/parsers.py`
- `main.py`

**What happens**

- Instead of sniffing traffic, TrafficSentinel reads **application logs**
- Recommended format: **JSONL**
- Logs are tailed continuously (offset-based, no duplicates)

**Why this works for HTTPS**

- HTTPS is decrypted **inside your app**
- Your app logs:
  - URI
  - Headers
  - Body
- TrafficSentinel analyzes those logs

✅ This is how **HTTPS streams are handled**

---

## 3. Parsing & Normalization

**Files involved**

- `analyzer/normalizer.py`
- `ingestor/parsers.py`

### What normalization does

Every input is cleaned and standardized:

- URL decoded (twice)
- Lowercased
- Null bytes removed
- Whitespace normalized

### Data buckets created

Each request is split into **separate scan targets**:

| Target         | Purpose                      |
| -------------- | ---------------------------- |
| uri            | Full URI                     |
| path           | Only path                    |
| query          | Raw query string             |
| query_params   | Parsed `key=value`           |
| headers        | Header values (excluding UA) |
| headers_kv     | `key: value`                 |
| cookies        | Cookie header                |
| cookies_params | Parsed cookies               |
| user_agent     | Dedicated UA bucket          |
| body           | Request body                 |
| combined       | Everything **except UA**     |

⚠️ **User-Agent is isolated** so it cannot ban users alone.

---

## 4. Detection Engine

**Files involved**

- `analyzer/detector.py`
- `analyzer/rules.py`
- `analyzer/rules_loader.py`
- `vendor/crs/`

### Rule sources

- OWASP CRS-inspired regex rules:
  - SQLi
  - XSS
  - RCE
  - LFI
  - PHP injection
- Custom rules (`rules_custom.yml`)
- Legacy rules (`rules_legacy.yml`)

### How scanning works

For each request:

1. Each rule is tested against relevant targets
2. Matches are recorded as **hits**
3. Hits are grouped by **category**

### Command Injection Heuristic

Extra logic checks for:

- Command separators (`; && | $()`)
- Known shell commands (Unix + PowerShell lists)

This catches payloads like:

```sh
id; uname -a
```

---

## 5. False-Positive Protection (Important)

### User-Agent protection

UA is scanned only for visibility
If only UA matches, then:
    score = 0
    No ban
    Logged as `ua_only=1`
This prevents bans like:
> “User got banned just for using curl / browser”

---

## 6. Scoring System

**Files involved**

- `analyzer/detector.py`
- `core/state.py`

### How score is calculated

Default mode: per-category

| Scenario         | Score |
|------------------|-------|
| SQLi + XSS       | 2     |
| Only UA match    | 0     |
| CMDi heuristic   | 1     |
| Bruteforce       | 1     |

Score represents **confidence**, not severity.

---

## 7. Stateful IP Reputation

**Files involved**

- `core/state.py`
- `state/reputation.json`

Each IP has:

- Total score
- Last seen time
- Strike count
- Ban expiry (temporary or permanent)

This prevents:

- One-off false bans
- Allows escalation on repeated attacks

---

## 8. Bruteforce Detection

### PCAP Bruteforce

Counts hits to `/login`, `/admin`, etc per minute

### Log Bruteforce

Counts failed auth responses (401/403)

Per-IP rate threshold

If exceeded:

- Adds bruteforce score

---

## 9. Firewall Enforcement (Auto-Ban)

**Files involved**

- `enforcer/firewall.py`

### What happens

A dedicated iptables chain (`TS_BLOCK`) is created

On ban:

```sh
iptables -A TS_BLOCK -s <ip> -j DROP
```

On expiry:

```sh
iptables -D TS_BLOCK -s <ip> -j DROP
```

Allowlist is respected (`core/allowlist.py`).

---

## 10. Logging & Visibility

**Files involved**

- `state/events.log`
- `state/actions.log`
- `state/error.log`
- optional: all_requests_log

### Logs explained

| Log              | Purpose                  |
|------------------|--------------------------|
| events.log       | Only malicious events    |
| actions.log      | Ban / unban actions      |
| error.log        | Internal errors          |
| all_requests_log | Full telemetry (optional)|

Example:

    ip=1.2.3.4 score=2 cats=sqli,xss ua_only=0

---

## 11. Main Orchestrator

**File**

- `main.py`

### What it does

- Loads config
- Chooses mode (PCAP or log)
- Runs capture / tail loop
- Feeds data to analyzer
- Updates state
- Enforces firewall
- Handles graceful shutdown

This is the **brain of the system**.

---

## 12. Summary (In One Sentence)

TrafficSentinel watches traffic (via PCAP or logs), normalizes requests, detects attacks using rules + heuristics, tracks IP reputation over time, and automatically blocks confirmed attackers—while protecting normal users from false positives.

**Recommended Mode**

✅ Log mode with JSONL
❌ PCAP for HTTPS content
