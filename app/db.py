import sqlite3
import pathlib
import subprocess
from datetime import datetime

DB_PATH = pathlib.Path(__file__).parent.parent / "data" / "netgate.db"
BLOCKLIST_CONF = "/etc/netgate/blocklist.conf"

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_domains (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            domain   TEXT UNIQUE NOT NULL,
            note     TEXT,
            created  TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def list_domains():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM blocked_domains ORDER BY created DESC").fetchall()
    conn.close()
    return rows

def clean_domain(domain: str) -> str:
    """Kullanicinin girdigi adresi temiz alan adina cevirir.
    Ornek: 'https://www.YouTube.com/feed' -> 'youtube.com'"""
    d = domain.strip().lower()
    # basindaki protokolu at
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    # basindaki www. at
    if d.startswith("www."):
        d = d[4:]
    # ilk / isaretinden sonrasini at (yol kismi)
    d = d.split("/")[0]
    # port varsa at
    d = d.split(":")[0]
    return d.strip()

def add_domain(domain: str, note: str = ""):
    domain = clean_domain(domain)
    if not domain:
        return False
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO blocked_domains (domain, note, created) VALUES (?, ?, ?)",
            (domain, note.strip(), datetime.now().strftime("%Y-%m-%d %H:%M"))
        )
        conn.commit()
        ok = True
    except sqlite3.IntegrityError:
        ok = False
    conn.close()
    if ok:
        apply_blocklist()
    return ok

def delete_domain(domain_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM blocked_domains WHERE id = ?", (domain_id,))
    conn.commit()
    conn.close()
    apply_blocklist()

def apply_blocklist():
    """Veritabanindaki siteleri dnsmasq formatinda dosyaya yazar ve dnsmasq'i yeniler."""
    domains = list_domains()
    lines = []
    for d in domains:
        dom = d["domain"]
        # IPv4 ve IPv6'yi birlikte blokla (yoksa IPv6 uzerinden siteye girilebilir)
        lines.append(f"address=/{dom}/0.0.0.0")
        lines.append(f"address=/{dom}/::")
    try:
        with open(BLOCKLIST_CONF, "w") as f:
            f.write("\n".join(lines) + "\n")
    except PermissionError:
        return False
    # dnsmasq'i yeniden yukle (systemctl reload)
    try:
        subprocess.run(["sudo", "systemctl", "reload", "dnsmasq"], check=False)
    except Exception:
        pass
    return True