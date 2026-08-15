"""NetGate 5651 - DNS loglarini kullanici bilgisiyle zenginlestirip yazar."""
import re
import time
import sys
sys.path.insert(0, "/home/yasin/netgate")
from app.db import get_conn

DNS_LOG = "/var/log/netgate-dns.log"
LOG_5651 = "/var/log/netgate-5651.log"

# IP -> (kullanici, mac) onbellek (performans icin)
_cache = {}
_cache_time = 0

def _refresh_sessions():
    """Aktif oturumlari IP->kullanici,mac olarak yukler."""
    global _cache, _cache_time
    now = time.time()
    if now - _cache_time < 5:  # 5 saniyede bir yenile
        return
    _cache = {}
    try:
        conn = get_conn()
        rows = conn.execute("SELECT ip, identity, mac FROM portal_sessions WHERE active=1").fetchall()
        conn.close()
        for r in rows:
            if r["ip"]:
                _cache[r["ip"]] = (r["identity"], r["mac"] or "?")
    except Exception:
        pass
    _cache_time = now

def _mac_from_arp(ip):
    import subprocess, re
    try:
        r = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=3)
        m = re.search(r"lladdr\s+([0-9a-f:]{17})", r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "?"

def _lookup(ip):
    _refresh_sessions()
    if ip in _cache:
        return _cache[ip]
    # Oturum yok - en azindan MAC'i ARP'tan bul
    return ("giris-yok", _mac_from_arp(ip))

# DNS log satiri: "Aug 15 12:42:36 dnsmasq[123]: 8900 10.10.0.108/54923 query[A] www.qq.com from 10.10.0.108"
QUERY_RE = re.compile(r"^(\w+\s+\d+\s+[\d:]+).*query\[[A]+\]\s+(\S+)\s+from\s+([\d.]+)")

def follow(path):
    """tail -f gibi dosyayi izler."""
    with open(path, "r") as f:
        f.seek(0, 2)  # sona git
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def main():
    for line in follow(DNS_LOG):
        m = QUERY_RE.search(line)
        if not m:
            continue
        ts, domain, ip = m.group(1), m.group(2), m.group(3)
        # Sadece LAN cihazlari
        if not ip.startswith("10.10."):
            continue
        user, mac = _lookup(ip)
        out = f"{ts} | {user} | {mac} | {ip} | {domain}\n"
        try:
            with open(LOG_5651, "a") as lf:
                lf.write(out)
        except Exception:
            pass

if __name__ == "__main__":
    main()
