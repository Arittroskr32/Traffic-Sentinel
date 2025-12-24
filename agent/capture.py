import subprocess
import datetime
import os
import yaml
from typing import Optional, Dict, Any

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")


def get_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def capture_traffic() -> Optional[str]:
    cfg = get_config()
    cap = cfg.get("capture", {}) or {}

    iface = cap.get("interface", "eth0")
    pcap_dir = cap.get("pcap_dir", "./pcap")
    slice_seconds = int(cap.get("slice_seconds", 60))
    tcpdump_path = cap.get("tcpdump_path", "tcpdump")
    bpf_filter = cap.get("bpf_filter", "tcp or udp")
    snaplen = int(cap.get("snaplen", 0))

    os.makedirs(pcap_dir, exist_ok=True)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"capture_{ts}.pcap"
    filepath = os.path.join(pcap_dir, filename)

    cmd = [
        tcpdump_path,
        "-i", iface,
        "-n",
        "-s", str(snaplen),
        "-U",
        "-G", str(slice_seconds),
        "-W", "1",
        "-w", filepath,
    ]

    if bpf_filter:
        # End options then pass filter expression as a single argument
        cmd += ["--", bpf_filter]

    try:
        subprocess.run(cmd, check=True)
    except Exception as e:
        print(f"[capture] Capture failed: {e}")
        return None

    return filepath
