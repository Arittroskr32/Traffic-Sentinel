# TrafficSentinel — How to Verify It Works (Demo Server Test Plan)

This guide shows how to **prove TrafficSentinel is working end-to-end** on a demo server, what files/logs to watch, what should change in `reputation.json`, and how detection/ban behavior should look in both **PCAP mode** and **Log ingestion mode (recommended for HTTPS)**.

---

## 0) Before You Start (What “Working” Means)

TrafficSentinel is working if you can confirm all of these:

- ✅ It is running continuously (docker/systemd)
- ✅ It reads traffic (PCAP or host logs)
- ✅ It detects attack patterns (rules match)
- ✅ It writes events to logs (`state/events.log`)
- ✅ It updates reputation state (`state/reputation.json`)
- ✅ It bans when threshold reached (iptables TS_BLOCK)
- ✅ It unbans after expiry (temporary bans)
- ✅ It never bans allowlisted/trusted tester IPs

---

## 1) Choose Your Test Mode

### Mode A — Log ingestion (Recommended for HTTPS)
Use this if your site is **HTTPS** (most real servers).

**Why:** HTTPS payload is encrypted, so PCAP cannot see URL/body. Logs *do* contain request path/status (and sometimes body).

### Mode B — PCAP mode (Plain HTTP / local testing)
Use this if you can serve the app in HTTP (port 80) or you want network-level metadata tests.

---

## 2) Confirm the Service is Running

### Docker
```bash
docker compose ps
docker logs -f trafficsentinel
```
### Systemd (optional deployment)
```bash
sudo systemctl status trafficsentinel
sudo journalctl -u trafficsentinel -f
```

## 3) Verify Firewall Hook (iptables)
TrafficSentinel should create a chain and insert a jump from INPUT.
```bash
sudo iptables -S | grep TS_BLOCK
sudo iptables -S INPUT | head -n 20
sudo iptables -L TS_BLOCK -n --line-numbers
```
Expected:
- A chain named TS_BLOCK
- A jump rule in INPUT: -j TS_BLOCK
- TS_BLOCK initially empty until bans occur

## 4) Verify Output Files (Logs + State)
TrafficSentinel writes to:
- state/events.log → detection events
- state/actions.log → ban/unban actions
- state/error.log → errors (must stay mostly empty)
- state/reputation.json → live reputation database
Check:
```bash
ls -lh state/
tail -n 50 state/events.log
tail -n 50 state/actions.log
tail -n 50 state/error.log
cat state/reputation.json | head -n 50
```

## 5) Understand What It Logs (Important)
### events.log (per request / per event)
Contains entries like:
- **timestamp**
- **source IP**
- **score** for that request (per_request mode = max 1)
- **number of hits/categories**

**Example meaning:**
- `score=1` means that request matched at least one category/pattern.
- `hits=N` means number of regex hits inside that request (but still max +1 penalty in per_request mode).

### actions.log (ban/unban)
Contains:
- ban action
- whether permanent
- (optional) reasons/categories if you log them

### reputation.json
For each IP:
- `penalty`: current points
- `last_seen`: last detection time
- `ban_until`: epoch timestamp if temp banned
- `ban_count`: number of bans so far
- `permanent`: true if permanently banned

---

## 6) Quick Health Checklist

### A) “No bans by mistake”
- Browse your site normally from your own IP
- `events.log` should not spam with scores
- `reputation.json` should not increase penalty for your normal browsing

### B) “Allowlist works”
If your IP is inside:
```yaml
allowlist:
	trusted_testers:
		- "YOUR_IP"
```
Then even if you send attacks:
- no penalty increase
- no ban rules added

**Check:**
```bash
python cli.py allowlist list
python cli.py show YOUR_IP
```

---

## 7) Test Attacks (Detection Proof)

> ⚠️ Do this only on your demo server and authorized environment.

Find your public IP (the client IP seen by the server):
- If testing from your laptop:
	```bash
	curl -s ifconfig.me
	```
- If testing from another server/VM:
	```bash
	curl -s https://api.ipify.org
	```

---

## 8) Test in Log Ingestion Mode (HTTPS Recommended)

### 8.1 Confirm logs are mounted into the container (Docker)
If using nginx host logs:
```yaml
volumes:
	- /var/log/nginx:/hostlogs:ro
```
Check inside container:
```bash
docker exec -it trafficsentinel ls -lah /hostlogs
docker exec -it trafficsentinel tail -n 5 /hostlogs/access.log
```

### 8.2 Send attacks via HTTPS
Replace domain with your demo site:
- **XSS**
	```bash
	curl -k "https://demo.example.com/search?q=<script>alert(1)</script>"
	```
- **SQLi**
	```bash
	curl -k "https://demo.example.com/login?user=admin' OR 1=1--"
	```
- **SSTI**
	```bash
	curl -k "https://demo.example.com/?name={{7*7}}"
	```
- **Command Injection**
	```bash
	curl -k "https://demo.example.com/ping?host=127.0.0.1;id"
	```

### 8.3 What you should see
- `state/events.log` new lines for your IP with `score=1`
- `state/reputation.json` penalty increases gradually
- After crossing `ban_threshold`, you’ll see:
	- `actions.log`: ban
	- `iptables -L TS_BLOCK`: DROP rule for your IP
	- you are blocked from connecting

---

## 9) Test in PCAP Mode (HTTP Only)
If your site is only HTTPS, PCAP mode will not see URI/body, so rule detection won’t work.

### 9.1 Confirm pcap generation
If you use pcap mode:
```bash
ls -lh pcap/
```
You should see files appear each minute and then be deleted after analysis.
If your loop deletes them immediately, you can temporarily disable deletion to inspect.

### 9.2 Ensure plain HTTP traffic exists
Try:
```bash
curl "http://demo.example.com/?q=<script>alert(1)</script>"
```
Then check:
- events/logs show detection
- if not, likely:
	- traffic is not on interface eth0
	- HTTP is not present (HTTPS only)
	- tshark filter http.request matches nothing

---

## 10) Bruteforce Detection (How It Detects)
Bruteforce logic is heuristic-based (not regex).

TrafficSentinel counts requests per IP to common auth endpoints, per minute.

**Endpoints usually include:**
- /login
- /signin
- /wp-login.php
- /admin
- /api/auth

**Log mode (best):**
If status codes are in logs, it can count only failed auth attempts:
- fail statuses: 401, 403

**Example bruteforce test:**
Run multiple login requests quickly:
```bash
for i in $(seq 1 25); do
	curl -k -s -o /dev/null -w "%{http_code}\n" "https://demo.example.com/login"
done
```
**Expected:**
- bruteforce category triggers when threshold exceeded (example: 10/min)
- penalty increments (+1 per minute window if configured that way)
- eventually leads to ban if repeated

---

## 11) Confirm Ban + Unban Works
When banned:
- Check iptables:
	```bash
	sudo iptables -L TS_BLOCK -n --line-numbers
	```
- Test that your IP can’t connect:
	```bash
	curl -k https://demo.example.com
	```
	**Expected:** timeout / blocked

**Unban after expiry:**
After `ban_seconds`, TrafficSentinel should remove the rule.
Check:
```bash
sudo iptables -L TS_BLOCK -n
tail -n 50 state/actions.log
```
**Expected:**
- actions log includes unban
- iptables rule removed

---

## 12) Admin CLI Verification (Manual Control)
- Show top attackers
	```bash
	python cli.py top -n 20
	```
- Show one IP
	```bash
	python cli.py show 1.2.3.4
	```
- Clear penalty
	```bash
	python cli.py clear 1.2.3.4
	```
- Unban IP (temporary)
	```bash
	python cli.py unban 1.2.3.4
	```
- Unban and clear permanent (force)
	```bash
	python cli.py unban 1.2.3.4 --force
	```
- Allowed Ip (Developer, pentester)
    ```bash
    python cli.py allowlist ( list / add 1.2.3.4/ remove 1.2.3.4)
    ```

---

## 13) What to Watch During Testing (Best Debug Workflow)
Open 3 terminals:
- **Terminal A** — TrafficSentinel logs
	```bash
	docker logs -f trafficsentinel
	```
- **Terminal B** — events/action logs
	```bash
	tail -f state/events.log
	```
- **Terminal C** — firewall rules
	```bash
	watch -n 1 "sudo iptables -L TS_BLOCK -n --line-numbers"
	```
Now run curl tests and you’ll see everything update live.

---

## 14) Common Problems (and Quick Fixes)
- **No detection in PCAP mode**
	- You are capturing wrong interface (try `ip a` and update `capture.interface`)
	- Your traffic is HTTPS (PCAP can’t see payload)
	- tshark not installed / missing permissions
	- filter mismatch (`http.request` won’t match)
- **No detection in log mode**
	- log file not mounted
	- wrong log_path
	- nginx log format missing required fields (IP, path)
	- container can’t read host logs (permissions)
- **Bans not enforced**
	- container not running with NET_ADMIN / privileged
	- iptables on host uses nft backend (still usually OK)
	- TS_BLOCK chain not created (check iptables output)

---

## 15) “Success Criteria” Checklist (Final)
You’re done when you can demonstrate:
- `events.log` grows with detections when you attack
- `reputation.json` penalty increases for attacker IP
- When threshold reached, `actions.log` shows ban
- `iptables` TS_BLOCK contains the banned IP
- The banned IP cannot access the site
- After ban expiry, it unbans automatically
- Allowlisted IPs never get banned even when testing