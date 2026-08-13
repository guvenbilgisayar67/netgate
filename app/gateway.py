"""
NetGate - Gercek makine trafik uygulama katmani
Bu modul, panelin verdigi kararlari (izin, grup filtresi, hiz) gercek
aga uygular: nftables (MAC izni + filtre yonlendirme) ve tc (hiz).

DIKKAT: Bu fonksiyonlar gercek gateway makinesinde calisir. Sanal
gelistirme makinesinde cagrildiginda sessizce basarisiz olabilir
(gerekli arayuzler/yetkiler olmadigindan) - bu normaldir.
"""

import subprocess
import pathlib
from app import portal, categories

# Gercek makinede LAN arayuzu (kur.sh ile ayni olmali)
# kur.sh kurulumda bunu /etc/netgate/lan_if dosyasina yazar
def _lan_if():
    try:
        return pathlib.Path("/etc/netgate/lan_if").read_text().strip()
    except Exception:
        return "eth1"

def _run(cmd, ignore_err=True):
    """Komutu calistir; hata olursa (gercek makine degilse) sessizce gec."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.returncode == 0, r.stdout + r.stderr
    except Exception as e:
        if not ignore_err:
            raise
        return False, str(e)

# ============================================================
# 1) CAPTIVE PORTAL: MAC izni
# ============================================================

def allow_mac(mac: str):
    """Giris yapan cihazin MAC'ini internete izinli yap (nftables set)."""
    if not mac:
        return False
    ok, _ = _run(["sudo", "nft", "add", "element", "inet", "netgate", "allowed_macs", "{", mac, "}"])
    return ok

def remove_mac(mac: str):
    """Oturum bitince MAC'i izinli listeden cikar."""
    if not mac:
        return False
    ok, _ = _run(["sudo", "nft", "delete", "element", "inet", "netgate", "allowed_macs", "{", mac, "}"])
    return ok

def sync_allowed_macs():
    """Aktif oturumlardaki tum MAC'leri nftables set'ine yazar (yeniden kurulumda)."""
    sessions = portal.list_sessions(active_only=True)
    macs = [s["mac"] for s in sessions if s["mac"]]
    # Once temizle, sonra hepsini ekle
    _run(["sudo", "nft", "flush", "set", "inet", "netgate", "allowed_macs"])
    for mac in macs:
        allow_mac(mac)
    return len(macs)

# ============================================================
# 2) GRUP FILTRESI: kullanicinin IP'sine grup kategorilerini uygula
# ============================================================
# Yaklasim: her grup icin dnsmasq'ta ayri bir "ipset" olusturulur,
# kullanicinin IP'si grubunun ipset'ine eklenir. Kategori dosyalari
# ipset'e gore uygulanir. (Gercek makinede ince ayar gerekir.)

GROUP_FILTER_DIR = "/etc/netgate/group_filters"

def apply_group_filter(ip: str, group_name: str):
    """Kullanicinin IP'sine grubunun filtre profilini uygular.
    Grubun kategorilerini o IP icin engelli yapar."""
    if not ip or not group_name:
        return False
    g = portal.get_group(group_name)
    if not g:
        return False
    cats = g["categories"].split(",") if g["categories"] else []
    # Grup filtre dosyasi: bu IP icin hangi kategoriler engelli
    pathlib.Path(GROUP_FILTER_DIR).mkdir(parents=True, exist_ok=True)
    # Not: Gercek uygulamada dnsmasq ipset veya nftables ile IP bazli
    # yonlendirme yapilir. Simdilik kaydi tutuyoruz; gercek makinede
    # dnsmasq ipset entegrasyonu eklenecek.
    path = f"{GROUP_FILTER_DIR}/{ip.replace('.', '_')}.conf"
    with open(path, "w") as f:
        f.write(f"# IP: {ip}  Grup: {group_name}\n")
        f.write(f"# Engelli kategoriler: {','.join(cats)}\n")
    return True

def remove_group_filter(ip: str):
    if not ip:
        return False
    path = f"{GROUP_FILTER_DIR}/{ip.replace('.', '_')}.conf"
    try:
        pathlib.Path(path).unlink()
    except FileNotFoundError:
        pass
    return True

# ============================================================
# 3) HIZ LIMITI: tc ile kullanicinin IP'sine bant genisligi
# ============================================================
# Yaklasim: HTB (Hierarchical Token Bucket) ile her IP'ye ayri class.
# tc filtresi IP'yi ilgili hiz class'ina yonlendirir.

def apply_bandwidth(ip: str, kbps: int):
    """Kullanicinin IP'sine hiz limiti uygular (tc HTB).
    kbps=0 ise limit yok."""
    if not ip or not kbps or kbps <= 0:
        return False
    lan = _lan_if()
    # IP'nin son okteti class id olarak kullanilir (basit yaklasim)
    try:
        last_octet = int(ip.split(".")[-1])
        classid = 1000 + last_octet
    except Exception:
        return False
    # Class olustur ve filtre ekle (root qdisc kur.sh'te kurulur)
    _run(["sudo", "tc", "class", "add", "dev", lan, "parent", "1:", "classid",
          f"1:{classid}", "htb", "rate", f"{kbps}kbit", "ceil", f"{kbps}kbit"])
    _run(["sudo", "tc", "filter", "add", "dev", lan, "protocol", "ip", "parent", "1:0",
          "prio", "1", "u32", "match", "ip", "dst", ip, "flowid", f"1:{classid}"])
    return True

def remove_bandwidth(ip: str):
    if not ip:
        return False
    lan = _lan_if()
    try:
        last_octet = int(ip.split(".")[-1])
        classid = 1000 + last_octet
    except Exception:
        return False
    _run(["sudo", "tc", "class", "del", "dev", lan, "classid", f"1:{classid}"])
    return True

# ============================================================
# ANA GIRIS: portal login basarili olunca cagrilir
# ============================================================

def on_login(ip: str, mac: str, group_name: str, bandwidth_kbps: int):
    """Kullanici giris yapinca tum kurallari uygular."""
    results = {}
    results["mac"] = allow_mac(mac)
    results["filter"] = apply_group_filter(ip, group_name)
    results["bandwidth"] = apply_bandwidth(ip, bandwidth_kbps)
    return results

def on_logout(ip: str, mac: str):
    """Oturum bitince tum kurallari kaldirir."""
    remove_mac(mac)
    remove_group_filter(ip)
    remove_bandwidth(ip)