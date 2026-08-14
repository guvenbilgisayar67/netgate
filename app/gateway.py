"""NetGate - Gercek makine trafik uygulama katmani"""
import subprocess
import pathlib
import re
from app import portal

def _lan_if():
    try:
        return pathlib.Path("/etc/netgate/lan_if").read_text().strip()
    except Exception:
        return "enp42s0"

def _run(cmd, ignore_err=True):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.returncode == 0, r.stdout + r.stderr
    except Exception as e:
        if not ignore_err:
            raise
        return False, str(e)

def mac_from_ip(ip):
    """IP adresinden MAC bulur (ip neigh / ARP tablosu)."""
    if not ip:
        return ""
    ok, out = _run(["ip", "neigh", "show", ip])
    if ok and out:
        m = re.search(r"lladdr\s+([0-9a-f:]{17})", out)
        if m:
            return m.group(1)
    return ""

# ---------- MAC izni ----------

def allow_mac(mac):
    if not mac:
        return False
    ok, _ = _run(["sudo", "nft", "add", "element", "inet", "netgate", "allowed_macs", "{", mac, "}"])
    return ok

def remove_mac(mac):
    if not mac:
        return False
    ok, _ = _run(["sudo", "nft", "delete", "element", "inet", "netgate", "allowed_macs", "{", mac, "}"])
    return ok

# ---------- Hiz limiti (tc) ----------

def apply_bandwidth(ip, kbps):
    if not ip or not kbps or kbps <= 0:
        return False
    lan = _lan_if()
    try:
        last_octet = int(ip.split(".")[-1])
        third_octet = int(ip.split(".")[-2])
        classid = 1000 + third_octet * 256 + last_octet
        classid = classid % 65535
    except Exception:
        return False
    # Onceki kurali temizle (varsa)
    _run(["sudo", "tc", "filter", "del", "dev", lan, "protocol", "ip", "parent", "1:0", "prio", "1"])
    _run(["sudo", "tc", "class", "del", "dev", lan, "classid", f"1:{classid}"])
    # Yeni kural
    _run(["sudo", "tc", "class", "add", "dev", lan, "parent", "1:", "classid",
          f"1:{classid}", "htb", "rate", f"{kbps}kbit", "ceil", f"{kbps}kbit"])
    _run(["sudo", "tc", "filter", "add", "dev", lan, "protocol", "ip", "parent", "1:0",
          "prio", "1", "u32", "match", "ip", "dst", ip, "flowid", f"1:{classid}"])
    return True

def remove_bandwidth(ip):
    if not ip:
        return False
    lan = _lan_if()
    try:
        last_octet = int(ip.split(".")[-1])
        third_octet = int(ip.split(".")[-2])
        classid = 1000 + third_octet * 256 + last_octet
        classid = classid % 65535
    except Exception:
        return False
    _run(["sudo", "tc", "filter", "del", "dev", lan, "protocol", "ip", "parent", "1:0", "prio", "1"])
    _run(["sudo", "tc", "class", "del", "dev", lan, "classid", f"1:{classid}"])
    return True

# ---------- Ana giris/cikis ----------

def on_login(ip, mac, group_name, bandwidth_kbps):
    # MAC bos ise IP'den bul
    if not mac:
        mac = mac_from_ip(ip)
    results = {}
    results["mac_found"] = mac
    results["mac"] = allow_mac(mac) if mac else False
    results["bandwidth"] = apply_bandwidth(ip, bandwidth_kbps)
    return results

def on_logout(ip, mac):
    if not mac:
        mac = mac_from_ip(ip)
    if mac:
        remove_mac(mac)
    remove_bandwidth(ip)
