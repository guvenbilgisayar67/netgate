import subprocess
import urllib.request
import pathlib
from app.db import get_conn

CATEGORY_DIR = "/etc/netgate/categories"

# Kategori tanimlari
# type "url"  -> internetten inen hosts listesi
# type "list" -> gomulu kucuk liste (kolej icin)
CATEGORIES = {
    "ads": {
        "name": "Reklam ve Izleyiciler",
        "desc": "Reklam sunuculari ve takip servisleri (StevenBlack)",
        "type": "url",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    },
    "adult": {
        "name": "Yetiskin Icerik",
        "desc": "Porno ve yetiskin siteleri (StevenBlack porn)",
        "type": "url",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
    },
    "social": {
        "name": "Sosyal Medya",
        "desc": "YouTube, Instagram, TikTok, Facebook, Twitter/X, Snapchat",
        "type": "list",
        "domains": [
            "youtube.com", "instagram.com", "tiktok.com", "facebook.com",
            "twitter.com", "x.com", "snapchat.com", "reddit.com",
        ],
    },
    "games": {
        "name": "Oyun Siteleri",
        "desc": "Populer oyun ve oyun dagitim platformlari",
        "type": "list",
        "domains": [
            "steampowered.com", "epicgames.com", "roblox.com",
            "twitch.tv", "ea.com", "battle.net",
        ],
    },
}

def init_categories():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS category_state (
            key      TEXT PRIMARY KEY,
            enabled  INTEGER NOT NULL DEFAULT 0,
            count    INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()
    pathlib.Path(CATEGORY_DIR).mkdir(parents=True, exist_ok=True)

def get_states():
    conn = get_conn()
    rows = conn.execute("SELECT key, enabled, count FROM category_state").fetchall()
    conn.close()
    state = {r["key"]: {"enabled": bool(r["enabled"]), "count": r["count"]} for r in rows}
    result = {}
    for key, cat in CATEGORIES.items():
        s = state.get(key, {"enabled": False, "count": 0})
        result[key] = {**cat, "enabled": s["enabled"], "count": s["count"]}
    return result

def _parse_hosts(text):
    """hosts formatindan (0.0.0.0 domain.com) alan adlarini cikarir."""
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            dom = parts[1].strip().lower()
            if dom and dom != "localhost" and "." in dom:
                domains.add(dom)
    return domains

def _write_category_file(key, domains):
    path = f"{CATEGORY_DIR}/{key}.conf"
    lines = []
    for dom in sorted(domains):
        lines.append(f"address=/{dom}/0.0.0.0")
        lines.append(f"address=/{dom}/::")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return len(domains)

def enable_category(key):
    cat = CATEGORIES.get(key)
    if not cat:
        return False, "Kategori bulunamadi"
    # Alan adlarini topla
    if cat["type"] == "url":
        try:
            req = urllib.request.Request(cat["url"], headers={"User-Agent": "NetGate"})
            text = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "ignore")
            domains = _parse_hosts(text)
        except Exception as e:
            return False, f"Liste indirilemedi: {e}"
    else:
        domains = set(cat["domains"])
    if not domains:
        return False, "Liste bos"
    count = _write_category_file(key, domains)
    # Durumu kaydet
    conn = get_conn()
    conn.execute(
        "INSERT INTO category_state (key, enabled, count) VALUES (?, 1, ?) "
        "ON CONFLICT(key) DO UPDATE SET enabled=1, count=?",
        (key, count, count)
    )
    conn.commit()
    conn.close()
    _reload_dnsmasq()
    return True, f"{count} site engellendi"

def disable_category(key):
    path = f"{CATEGORY_DIR}/{key}.conf"
    try:
        pathlib.Path(path).unlink()
    except FileNotFoundError:
        pass
    conn = get_conn()
    conn.execute(
        "INSERT INTO category_state (key, enabled, count) VALUES (?, 0, 0) "
        "ON CONFLICT(key) DO UPDATE SET enabled=0, count=0",
        (key,)
    )
    conn.commit()
    conn.close()
    _reload_dnsmasq()
    return True, "Kategori kapatildi"

def _reload_dnsmasq():
    try:
        subprocess.run(["sudo", "systemctl", "reload", "dnsmasq"], check=False, timeout=10)
    except Exception:
        pass