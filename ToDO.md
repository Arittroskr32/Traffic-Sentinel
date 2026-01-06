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
sudo rm -f /etc/nginx/sites-enabled/default
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

---

# an important setup on which endpoint i want to check this like /post, /profile, /contact. 

## for this 
```
sudo nano /etc/nginx/conf.d/trafficsentinel_body.conf
```
here:
```json
map $request_uri $ts_capture_body {
    default 0;
    ~^/post/[0-9]+$ 1;
    ~^/profile/[0-9]+$ 1;
}
```
then do:
```
sudo nginx -t && sudo systemctl reload nginx
```
---


# after all setup to make run.py automatically run:
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

# If you are behind cloudfare:

## then do this:
Add this file:
```
sudo nano /etc/nginx/conf.d/realip.conf
```
put this:
```
real_ip_header CF-Connecting-IP;

# Trust Cloudflare IP ranges
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
real_ip_recursive on;
```

---