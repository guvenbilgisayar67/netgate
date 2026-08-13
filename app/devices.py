import subprocess
import re

LEASE_PATHS = [
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dnsmasq/dnsmasq.leases",
]

def _read_leases():
    """dnsmasq DHCP lease dosyasindan cihazlari okur.
    Satir formati: <bitis_zamani> <mac> <ip> <hostname> <client_id>"""
    devices = {}
    for path in LEASE_PATHS:
        try:
            with open(path) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        mac = parts[1].lower()
                        ip = parts[2]
                        host = parts[3] if parts[3] != "*" else ""
                        devices[ip] = {"ip": ip, "mac": mac, "host": host, "source": "DHCP"}
            break  # ilk bulunan dosyayi kullan
        except FileNotFoundError:
            continue
    return devices

def _read_arp():
    """ip neigh (ARP tablosu) - o an agda gorunen cihazlar."""
    devices = {}
    try:
        out = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return devices
    for line in out.splitlines():
        # Ornek: 192.168.1.103 dev enp0s3 lladdr 88:b1:11:ea:ac:b8 REACHABLE
        m = re.match(r"(\S+)\s+dev\s+\S+\s+lladdr\s+(\S+)\s+(\S+)", line)
        if m:
            ip, mac, state = m.group(1), m.group(2).lower(), m.group(3)
            if ip.count(".") == 3:  # sadece IPv4
                devices[ip] = {"ip": ip, "mac": mac, "host": "", "source": "ARP", "state": state}
    return devices

def list_devices():
    """DHCP lease + ARP birlestirip tek cihaz listesi dondurur."""
    leases = _read_leases()
    arp = _read_arp()
    # Once lease bilgisi (isim var), sonra ARP ile tamamla/guncelle
    merged = dict(arp)
    for ip, dev in leases.items():
        if ip in merged:
            merged[ip]["host"] = dev["host"] or merged[ip].get("host", "")
            merged[ip]["source"] = "DHCP"
        else:
            merged[ip] = dev
    result = list(merged.values())
    for d in result:
        d.setdefault("host", "")
        d.setdefault("state", "")
    result.sort(key=lambda d: [int(x) for x in d["ip"].split(".")] if d["ip"].count(".")==3 else [0,0,0,0])
    return result

def device_count():
    return len(list_devices())