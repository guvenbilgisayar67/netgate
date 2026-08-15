"""NetGate - Ag baglanti bilgisi (WAN/LAN port durumu, hiz, IP, trafik)"""
import subprocess
import time

WAN_IF = "enp5s0"
LAN_IF = "enp42s0"

_cached_public_ip = {"ip": "-", "ts": 0}

def _read(path, default="?"):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return default

def _ip_of(iface):
    try:
        out = subprocess.run(["ip", "-brief", "addr", "show", iface],
                             capture_output=True, text=True, timeout=3).stdout
        for p in out.split():
            if "." in p and "/" in p:
                return p
    except Exception:
        pass
    return "-"

def get_public_ip(max_age=60):
    now = time.time()
    if now - _cached_public_ip["ts"] < max_age and _cached_public_ip["ip"] != "-":
        return _cached_public_ip["ip"]
    for url in ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]:
        try:
            out = subprocess.run(["curl", "-s", "--max-time", "4", url],
                                 capture_output=True, text=True, timeout=6).stdout.strip()
            if out and "." in out and len(out) < 40:
                _cached_public_ip["ip"] = out
                _cached_public_ip["ts"] = now
                return out
        except Exception:
            continue
    return _cached_public_ip["ip"]

def _iface_info(iface):
    speed = _read(f"/sys/class/net/{iface}/speed", "?")
    operstate = _read(f"/sys/class/net/{iface}/operstate", "?")
    rx = _read(f"/sys/class/net/{iface}/statistics/rx_bytes", "0")
    tx = _read(f"/sys/class/net/{iface}/statistics/tx_bytes", "0")
    return {
        "iface": iface,
        "speed": speed,
        "up": operstate == "up",
        "ip": _ip_of(iface),
        "rx_bytes": int(rx) if rx.isdigit() else 0,
        "tx_bytes": int(tx) if tx.isdigit() else 0,
    }

def get_network_info():
    return {
        "wan": _iface_info(WAN_IF),
        "lan": _iface_info(LAN_IF),
        "public_ip": get_public_ip(),
    }

def get_traffic_counters():
    w = _iface_info(WAN_IF)
    l = _iface_info(LAN_IF)
    return {
        "wan_rx": w["rx_bytes"], "wan_tx": w["tx_bytes"],
        "lan_rx": l["rx_bytes"], "lan_tx": l["tx_bytes"],
    }
