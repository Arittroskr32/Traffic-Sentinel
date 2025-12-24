![Python](https://img.shields.io/badge/python-3.12+-blue.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue.svg)
![Security](https://img.shields.io/badge/security-defense-critical)
![Status](https://img.shields.io/badge/status-active-success.svg)

# TrafficSentinel

TrafficSentinel is a **rule-based traffic detection and automated enforcement system** designed to detect web attacks, abuse, and automated threats in real time, assign penalties, and apply firewall-based bans.

It is intentionally **simple, explainable, and deterministic**, focusing on practical security enforcement rather than opaque ML or anomaly-based models.

TrafficSentinel operates in **two complementary modes**:

- **PCAP Capture Mode** — network-level visibility (plaintext HTTP + metadata)
- **Log Ingestion Mode (Recommended)** — full HTTPS-capable application-layer detection

---

## Core Capabilities

### What TrafficSentinel Can Detect

#### Application-layer attacks (HTTP / HTTPS via logs)
- **XSS (Cross-Site Scripting)**
- **SQL Injection**
- **SSTI (Server-Side Template Injection)**
- **Command Injection / RCE**
- **Local File Inclusion (LFI)**
- **PHP-specific attacks**
- **Suspicious payload patterns** (via OWASP CRS-derived rules)

Detection works by matching normalized request data against compiled rule patterns.

#### Abuse & Automation
- **Bruteforce attacks**
  - Per-IP, per-minute detection
  - Auth endpoint hit-rate analysis
  - Log mode: counts failed attempts (401/403) when available
- **High-rate malicious request patterns**
- **Repeated attack attempts across multiple requests**

#### Network-level metadata (PCAP mode)
- Connection-level observation (all ports)
- HTTP payload inspection when traffic is unencrypted
- Foundation for future scan / SYN / flood detection

---

## Operating Modes

### 1) PCAP Mode (Network Capture)

- Captures live traffic using `tcpdump` in **60-second slices**
- Parses packets using `tshark`
- Extracts:
  - Source IP
  - HTTP URI
  - Headers (User-Agent, Host, Cookie)
  - Body (when available)
- Suitable for:
  - Plain HTTP traffic
  - Local testing
  - Network-level visibility

> Note: HTTPS payloads are encrypted and cannot be inspected in PCAP mode.

---

### 2) Log Ingestion Mode (Recommended for HTTPS)

- Continuously tails server/application logs
- Supports:
  - Common access logs
  - JSONL structured logs
- Extracts:
  - Client IP
  - URI (path + query)
  - Headers (if logged)
  - Request body (if logged)
  - Response status (for accurate bruteforce detection)
- Enables **full vulnerability detection on HTTPS traffic**

This mode provides the **highest accuracy** and is production-recommended.

---

## Detection Engine

### Rules System

- **CRS-derived rules** compiled from vendor OWASP CRS files
- **Custom rules** supported
- Rules are:
  - Regex-based
  - Categorized by vulnerability type
  - Scored uniformly (1 point per request)

Rules are **loaded once at startup** and reused for performance.

### Scoring Model

- **Per-request scoring**
  - Each request can add **at most +1 penalty**
  - Prevents score inflation from multiple matches in a single request
- Multiple malicious requests increase penalty cumulatively

---

## Reputation & Enforcement

### Reputation State

Stored in `state/reputation.json`, tracking per IP:
- `penalty`
- `last_seen`
- `ban_until`
- `ban_count`
- `permanent`

### Penalty Logic

- Penalty decays after inactivity (`decay_seconds`)
- Temporary ban when penalty ≥ threshold
- Permanent ban after repeated temporary bans
- Allowlisted IPs are never penalized

### Firewall Enforcement

- Uses **iptables**
- Dedicated chain: `TS_BLOCK`
- Automatically:
  - Applies bans
  - Removes expired bans
  - Prevents duplicate firewall rules

---

## Bruteforce Detection

### PCAP Mode
- Counts requests to authentication endpoints per IP per minute
- Threshold-based detection (+1 score)

### Log Mode (More Accurate)
- Counts authentication endpoint hits
- Uses response status codes (401/403) when available
- Detects credential-stuffing and password spraying

---

## Logging

### Logs Produced

- `state/events.log`
  - Every detection event
  - IP, score, categories, hit count

- `state/actions.log`
  - Ban events (with reason categories)
  - Unban events (with reason: expired)
  - Permanent bans

- `state/error.log`
  - Capture, parse, or enforcement errors

Logs are append-only and suitable for rotation.

---

## Rules Maintenance

- **Authoritative rule files**
  - `config/rules_custom.yml` — your custom rules
  - `config/rules_compiled.yml` — auto-generated (do not edit)
- To update CRS-based rules:
  1. Update vendor CRS `.conf` files
  2. Run `scripts/compile_rules.py`
- Builds are reproducible when vendor rules are versioned

---

## Security Model & Limitations

### What It Does Well
- Detects real application-layer attacks
- Enforces automated bans safely
- Works without modifying application code (log mode excepted)
- Lightweight, explainable, rule-based logic

### Known Limitations
- Cannot inspect encrypted HTTPS payloads without logs
- Not a replacement for a full WAF
- No behavioral ML or anomaly detection (by design)
- No distributed coordination (single-host scope)

---

## Project Structure

