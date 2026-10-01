"""NetGate - Cihaz tarama ve muaf cihaz yonetimi"""
import subprocess
import re
from app.db import get_conn


def _lan_if():
    try:
        with open("/etc/netgate/lan_if") as f:
            v = f.read().strip()
            return v if v else "enp42s0"
    except Exception:
        return "enp42s0"

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
    try:
        conn.execute("ALTER TABLE exempt_devices ADD COLUMN profile TEXT DEFAULT '_muaf'")
    except Exception:
        pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS device_names (
            mac     TEXT PRIMARY KEY,
            name    TEXT,
            updated TEXT
        )
    """)
    conn.commit()
    conn.close()

def _lease_map():
    """DHCP lease dosyasindan guncel {mac: ip} eslemesi."""
    m = {}
    try:
        with open("/var/lib/misc/dnsmasq.leases") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[2].startswith("10.10."):
                    m[parts[1].lower()] = parts[2]
    except Exception:
        pass
    return m

def get_device_names():
    """Elle verilen cihaz isimleri: {mac: isim}."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT mac, name FROM device_names").fetchall()
    except Exception:
        rows = []
    conn.close()
    return {r["mac"]: r["name"] for r in rows if r["name"]}

def set_device_name(mac, name):
    """Bir cihaza elle isim verir (bossa ismi siler)."""
    from datetime import datetime
    mac = (mac or "").strip().lower()
    name = (name or "").strip()
    if not mac:
        return False
    conn = get_conn()
    if name:
        conn.execute("INSERT INTO device_names (mac, name, updated) VALUES (?, ?, ?) "
                     "ON CONFLICT(mac) DO UPDATE SET name=?, updated=?",
                     (mac, name, datetime.now().strftime("%Y-%m-%d %H:%M"), name, datetime.now().strftime("%Y-%m-%d %H:%M")))
    else:
        conn.execute("DELETE FROM device_names WHERE mac=?", (mac,))
    conn.commit()
    conn.close()
    return True

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

def arp_scan():
    """arp-scan ile agi AKTIF tarar - gercek anlik cihazlar. isim DHCP lease'ten."""
    import time, subprocess
    devices = {}
    # DHCP lease'ten isim eslemesi (once yukle)
    names = {}
    now = time.time()
    try:
        with open("/var/lib/misc/dnsmasq.leases") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        exp = int(parts[0])
                    except ValueError:
                        exp = 0
                    nm = parts[3] if parts[3] != "*" else ""
                    names[parts[1].lower()] = nm
    except Exception:
        pass
    # arp-scan calistir
    try:
        out = subprocess.run(
            ["sudo", "arp-scan", f"--interface={_lan_if()}", "--localnet", "--quiet", "--ignoredups"],
            capture_output=True, text=True, timeout=25
        ).stdout
    except Exception:
        return list_devices()  # arp-scan basarisizsa eski yonteme dus
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            ip = parts[0].strip()
            mac = parts[1].strip().lower()
            if ip.startswith("10.10.") and len(mac) == 17:
                devices[mac] = {"ip": ip, "mac": mac, "name": names.get(mac, "")}
    # Muaf bilgisi ekle
    exempt_macs = {d["mac"] for d in list_exempt()}
    # DHCP almis MAC'ler (lease dosyasindan)
    dhcp_macs = set(names.keys())
    # Online (internete cikan) MAC'ler - allowed_macs setinden
    online_macs = set()
    try:
        nft_out = subprocess.run(["sudo", "nft", "list", "set", "inet", "netgate", "allowed_macs"],
                                 capture_output=True, text=True, timeout=5).stdout
        import re as _re
        for mm in _re.findall(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", nft_out):
            online_macs.add(mm.lower())
    except Exception:
        pass
    result = list(devices.values())
    for d in result:
        d["exempt"] = d["mac"] in exempt_macs
        if d["mac"] in online_macs or d["exempt"]:
            d["status"] = "online"
        elif d["mac"] in dhcp_macs:
            d["status"] = "bagli"
        else:
            d["status"] = "agda"
    manual = get_device_names()
    for d in result:
        if manual.get(d["mac"]):
            d["name"] = manual[d["mac"]]
    result.sort(key=lambda x: tuple(int(o) for o in x["ip"].split(".")))
    return result

def list_devices():
    """Taranan cihazlar + muaf olup olmadiklari."""
    scanned = scan_network()
    exempt_macs = {d["mac"] for d in list_exempt()}
    manual = get_device_names()
    for d in scanned:
        d["exempt"] = d["mac"] in exempt_macs
        if manual.get(d["mac"]):
            d["name"] = manual[d["mac"]]
    return scanned

# ---------- Muaf cihazlar ----------

def list_exempt():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM exempt_devices ORDER BY id").fetchall()
    conn.close()
    out = [dict(r) for r in rows]
    # Gosterim icin: guncel IP (DHCP lease) + elle verilen isim overlay
    leases = _lease_map()
    manual = get_device_names()
    for d in out:
        mac = (d.get("mac") or "").lower()
        d["cur_ip"] = leases.get(mac) or d.get("ip") or ""
        d["disp_name"] = manual.get(mac) or d.get("name") or ""
    return out

def add_exempt(mac, ip="", name="", profile="_muaf"):
    from datetime import datetime
    mac = mac.strip().lower()
    if not mac:
        return False
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO exempt_devices (mac, ip, name, added, profile) VALUES (?, ?, ?, ?, ?)",
            (mac, ip, name, datetime.now().strftime("%Y-%m-%d %H:%M"), profile)
        )
        conn.commit()
    except Exception:
        conn.close()
        return False
    conn.close()
    # Gateway'e hemen ekle (allowed_macs + muaf DNS profili - MAC bazli yonlendirme)
    try:
        from app import gateway, filters
        gateway.allow_mac(mac)
        port = filters.profile_port(profile)
        if port:
            gateway.set_dns_route_mac(mac, port)
        # Eski IP-bazli kalinti varsa temizle (artik MAC ile yonlendiriyoruz)
        if ip:
            gateway.clear_dns_route(ip)
    except Exception:
        pass
    return True

def remove_exempt(dev_id):
    conn = get_conn()
    row = conn.execute("SELECT mac, ip FROM exempt_devices WHERE id=?", (dev_id,)).fetchone()
    conn.execute("DELETE FROM exempt_devices WHERE id=?", (dev_id,))
    conn.commit()
    conn.close()
    # Gateway'den cikar
    if row:
        try:
            from app import gateway
            gateway.remove_mac(row["mac"])
            gateway.clear_dns_route_mac(row["mac"])
            if row["ip"]:
                gateway.clear_dns_route(row["ip"])
        except Exception:
            pass

def sync_exempt_to_gateway():
    """Tum muaf cihazlari allowed_macs'e yukler (baslangicta/reboot sonrasi)."""
    from app import gateway, filters
    count = 0
    # Portlari BIR KEZ hesapla (cihaz basina DB acmaktan kacin -> acilista kilit olmaz)
    try:
        ports = {p["name"]: p["port"] for p in filters.list_profiles()}
    except Exception:
        ports = {}
    for d in list_exempt():
        # Her cihaz ayri try/except: tek bir hata tum senkronu durdurmasin
        try:
            if gateway.allow_mac(d["mac"]):
                count += 1
            prof = d["profile"] if d.get("profile") else "_muaf"
            port = ports.get(prof)
            if port:
                gateway.set_dns_route_mac(d["mac"], port)
            # Eski IP-bazli kalinti temizligi
            if d.get("ip"):
                gateway.clear_dns_route(d["ip"])
        except Exception:
            continue
    return count


def change_exempt_profile(dev_id, profile):
    """Muaf cihazin filtre seviyesini (profilini) degistirir + yonlendirmeyi guncelle."""
    conn = get_conn()
    row = conn.execute("SELECT mac, ip FROM exempt_devices WHERE id=?", (dev_id,)).fetchone()
    conn.execute("UPDATE exempt_devices SET profile=? WHERE id=?", (profile, dev_id))
    conn.commit()
    conn.close()
    if row and row["mac"]:
        try:
            from app import gateway, filters
            port = filters.profile_port(profile)
            if port:
                gateway.set_dns_route_mac(row["mac"], port)
        except Exception:
            pass
    return True
