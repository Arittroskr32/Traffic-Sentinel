# Steup my server fully for this project:

## setup docker && docker compose
```
sudo apt update && sudo apt upgrade -y
sudo apt install -y ca-certificates curl gnupg lsb-release unzip
```
then
```
sudo apt remove -y docker docker-engine docker.io containerd runc
```
then
```
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
```
then
```
echo \
"deb [arch=$(dpkg --print-architecture) \
signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(lsb_release -cs) stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```
then
```
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io
```
then
```
sudo systemctl enable docker
sudo systemctl start docker
```
then check docker && docker compose
```
docker --version
docker compose version
```

---

# Install Nginx (reverse proxy + logging)
```
sudo apt install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
```
## Configure Nginx for Flask (PORT 80 FIX)
Create a new file:
```
sudo nano /etc/nginx/conf.d/trafficsentinel_jsonlog.conf
```
Paste here this:
```
log_format trafficsentinel_json escape=json
'{'
  '"ts":"$time_iso8601",'
  '"remote_addr":"$remote_addr",'
  '"host":"$host",'
  '"server_addr":"$server_addr",'
  '"method":"$request_method",'
  '"uri":"$uri",'
  '"args":"$args",'
  '"status":$status,'
  '"bytes":$body_bytes_sent,'
  '"ref":"$http_referer",'
  '"ua":"$http_user_agent"'
'}';
```

then also check this -> in `nano config/config.yml` here:

Set ingestion like this:
```bash
ingestion:
  log_source: "jsonl"
  log_path: "/var/log/nginx/vulnbook_access.jsonl"
  target_hosts: []          # optional: ["yourdomain.com"]
  target_server_ips: []     # optional: ["YOUR_SERVER_IP"]
```

then first remove this:
```
sudo nano /etc/nginx/sites-available/vulnbook
```
then in `sudo nano /etc/nginx/sites-available/vulnbook` :
here paste this
```
server {
    listen 80;
    server_name _;

    client_max_body_size 50m;

    access_log /var/log/nginx/vulnbook_access.jsonl trafficsentinel_json;
    error_log  /var/log/nginx/vulnbook_error.log;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

then check `config/config.yml` :
```
ingestion:
  log_source: jsonl
  log_path: /var/log/nginx/vulnbook_access.jsonl
```

then restart nginx :
```
sudo nginx -t 
sudo systemctl reload nginx
```

---
# Now in 2nd part



# To check POST body part also
## 1) Install nginx njs module
```
sudo apt update
sudo apt install -y nginx-module-njs
```
Then confirm it exists:
```
ls /usr/lib/nginx/modules/ | grep njs
```

## ✅ 2) Create /etc/nginx/ts_body.js (NEW FILE)
```
function body(r) {
  // r.requestText exists only if request body was read
  // keep it small: max 2048 chars
  var b = r.requestText || "";
  if (b.length > 2048) b = b.slice(0, 2048);
  return b;
}

export default { body };
```
## Replace your current JSONL logging section with this:
then find:
```
ls -l /etc/nginx/sites-enabled/
```
## ✅ (recommended): paste this fully
```
sudo tee /etc/nginx/conf.d/trafficsentinel_body.conf >/dev/null <<'NGINX'
# NJS script import for body extraction
js_import ts from /etc/nginx/ts_body.js;

# Only capture body for selected endpoints
map $request_uri $ts_capture_body {
    default 0;
    ~^/post/[0-9]+$ 1;
}

# If capture enabled, expose body via js; else blank
map $ts_capture_body $ts_body {
    default "";
    1       ${ts.body};
}

# JSONL log format (adds "body")
log_format ts_json escape=json
  '{"ts":"$time_iso8601",'
  '"remote_addr":"$remote_addr",'
  '"xff":"$http_x_forwarded_for",'
  '"host":"$host",'
  '"server_addr":"$server_addr",'
  '"request":"$request",'
  '"method":"$request_method",'
  '"uri":"$uri",'
  '"args":"$args",'
  '"status":$status,'
  '"bytes":$body_bytes_sent,'
  '"ref":"$http_referer",'
  '"ua":"$http_user_agent",'
  '"body":"$ts_body"'
  '}';
NGINX
```

then inside my `sudo nano /etc/nginx/sites-available/vulnbook
` file:
make this file `access_log` to:
```
sudo nano /etc/nginx/sites-available/vulnbook
access_log /var/log/nginx/vulnbook_access.jsonl ts_json;
js_set $ts_body_var $ts_body;
```

# Touch variable so nginx reads request body for r.requestText reliably

then at the last do:
```
sudo nginx -t
sudo systemctl reload nginx
```

---

# Check Logs of the server:
```bash
sudo tail -n 15 /var/log/nginx/vulnbook_access.jsonl
```


# after all setup to make run.py automatically run:
do this:
```
sudo nano /etc/systemd/system/trafficsentinel.service
```
here do this:
```
[Unit]
Description=TrafficSentinel Log Monitor
After=network.target docker.service nginx.service
Wants=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/Traffic-Sentinel

ExecStart=/usr/bin/python3 /root/Traffic-Sentinel/cli.py run
Restart=always
RestartSec=3

# Logging
StandardOutput=journal
StandardError=journal

# Hardening (safe defaults)
NoNewPrivileges=true
PrivateTmp=true

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
sudo systemctl status trafficsentinel --no-pager -l
```

---

# lastly
```
sudo rm -f /etc/systemd/system/trafficsentinel.service
sudo systemctl daemon-reload
```

```
sudo systemctl disable trafficsentinel 2>/dev/null || true
sudo systemctl stop trafficsentinel 2>/dev/null || true
```
then 
```
sudo crontab -l
crontab -l
```
then
```
sudo rm -f /etc/nginx/conf.d/trafficsentinel_jsonlog.conf
sudo nginx -t && sudo systemctl reload nginx
```