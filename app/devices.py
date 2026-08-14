"""NetGate - Cihaz tarama ve muaf cihaz yonetimi"""
import subprocess
import re
from app.db import get_conn

def init_devices():
    """Muaf cihazlar tablosunu olustur."""
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS exempt_devices (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            mac     TEXT UNIQUE,
            ip      TEXT,
            name    TEXT,
            added   TEXT
        )
    """)
    conn.commit()
    conn.close()

def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout
    except Exception:
        return ""

def scan_network():
    """Agdaki cihazlari tarar (ARP + DHCP lease). MAC/IP/isim listesi doner."""
    devices = {}

    # 1) ip neigh (ARP tablosu) - aktif cihazlar
    out = _run(["ip", "neigh", "show"])
    for line in out.splitlines():
        # ornek: 10.10.3.90 dev enp42s0 lladdr f4:b5:20:2d:f4:b7 REACHABLE
        m = re.match(r"([\d.]+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})", line)
        if m:
            ip, mac = m.group(1), m.group(2)
            # Sadece LAN cihazlari (10.10.x)
            if ip.startswith("10.10."):
                devices[mac] = {"ip": ip, "mac": mac, "name": ""}

    # 2) DHCP lease dosyasi - isim bilgisi
    lease_out = _run(["cat", "/var/lib/misc/dnsmasq.leases"])
    for line in lease_out.splitlines():
        # ornek: 1699999999 f4:b5:20:2d:f4:b7 10.10.3.90 laptop-adi *
        parts = line.split()
        if len(parts) >= 4:
            mac, ip, name = parts[1], parts[2], parts[3]
            if mac in devices:
                devices[mac]["name"] = name if name != "*" else ""
            elif ip.startswith("10.10."):
                devices[mac] = {"ip": ip, "mac": mac, "name": name if name != "*" else ""}

    return list(devices.values())

def device_count():
    """Aktif cihaz sayisi."""
    return len(scan_network())

def list_devices():
    """Taranan cihazlar + muaf olup olmadiklari."""
    scanned = scan_network()
    exempt_macs = {d["mac"] for d in list_exempt()}
    for d in scanned:
        d["exempt"] = d["mac"] in exempt_macs
    return scanned

# ---------- Muaf cihazlar ----------

def list_exempt():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM exempt_devices ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def add_exempt(mac, ip="", name=""):
    from datetime import datetime
    mac = mac.strip().lower()
    if not mac:
        return False
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO exempt_devices (mac, ip, name, added) VALUES (?, ?, ?, ?)",
            (mac, ip, name, datetime.now().strftime("%Y-%m-%d %H:%M"))
        )
        conn.commit()
    except Exception:
        conn.close()
        return False
    conn.close()
    # Gateway'e hemen ekle (allowed_macs)
    try:
        from app import gateway
        gateway.allow_mac(mac)
    except Exception:
        pass
    return True

def remove_exempt(dev_id):
    conn = get_conn()
    row = conn.execute("SELECT mac FROM exempt_devices WHERE id=?", (dev_id,)).fetchone()
    conn.execute("DELETE FROM exempt_devices WHERE id=?", (dev_id,))
    conn.commit()
    conn.close()
    # Gateway'den cikar
    if row:
        try:
            from app import gateway
            gateway.remove_mac(row["mac"])
        except Exception:
            pass

def sync_exempt_to_gateway():
    """Tum muaf cihazlari allowed_macs'e yukler (baslangicta/reboot sonrasi)."""
    from app import gateway
    count = 0
    for d in list_exempt():
        if gateway.allow_mac(d["mac"]):
            count += 1
    return count
