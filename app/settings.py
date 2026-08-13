import subprocess
import shutil
import json
from datetime import datetime
from app import db

def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return ""

def system_info():
    """Sistem saglik bilgileri: uptime, disk, RAM, servis durumlari."""
    info = {}

    # Calisma suresi
    info["uptime"] = _run(["uptime", "-p"]) or "-"

    # Disk kullanimi (kok dizin)
    total, used, free = shutil.disk_usage("/")
    info["disk_total"] = f"{total // (1024**3)} GB"
    info["disk_used"] = f"{used // (1024**3)} GB"
    info["disk_free"] = f"{free // (1024**3)} GB"
    info["disk_percent"] = round(used / total * 100)

    # RAM (free komutu)
    mem = _run(["free", "-m"])
    info["ram_total"] = "-"
    info["ram_used"] = "-"
    info["ram_percent"] = 0
    for line in mem.splitlines():
        if line.startswith("Mem:"):
            parts = line.split()
            if len(parts) >= 3:
                total_m = int(parts[1])
                used_m = int(parts[2])
                info["ram_total"] = f"{total_m} MB"
                info["ram_used"] = f"{used_m} MB"
                info["ram_percent"] = round(used_m / total_m * 100) if total_m else 0

    # Servis durumlari
    info["dnsmasq"] = _run(["systemctl", "is-active", "dnsmasq"]) or "unknown"
    info["netgate"] = _run(["systemctl", "is-active", "netgate"]) or "unknown"

    # DNS ust sunuculari (dnsmasq config'den)
    upstreams = []
    servers = _run(["sh", "-c", "grep -h '^server=' /etc/dnsmasq.d/*.conf 2>/dev/null"])
    for line in servers.splitlines():
        if line.startswith("server="):
            upstreams.append(line.split("=", 1)[1])
    info["dns_upstreams"] = upstreams or ["-"]

    return info

def export_config():
    """Engelli site listesini ve kullanicilari disa aktarir (JSON)."""
    domains = [{"domain": d["domain"], "note": d["note"]} for d in db.list_domains()]
    return {
        "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "blocked_domains": domains,
    }

def import_config(data: dict):
    """Disa aktarilmis engelli site listesini geri yukler."""
    count = 0
    for item in data.get("blocked_domains", []):
        dom = item.get("domain", "")
        note = item.get("note", "")
        if dom and db.add_domain(dom, note):
            count += 1
    return count