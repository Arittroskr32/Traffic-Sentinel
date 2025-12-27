FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

# Log-ingestion mode only (no PCAP capture). We keep iptables so bans can be applied.
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# Default: run via CLI so flags like --interval can be used easily
CMD ["python3", "cli.py", "run"]
