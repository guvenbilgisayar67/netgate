import sqlite3
import secrets
import string
from datetime import datetime, timedelta
from app.db import get_conn
import bcrypt

def init_portal():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_settings (
            key TEXT PRIMARY KEY, value TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            group_name TEXT NOT NULL DEFAULT 'ogrenci',
            duration_min INTEGER NOT NULL DEFAULT 60,
            bandwidth_kbps INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            created TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_groups (
            name TEXT PRIMARY KEY,
            categories TEXT,
            bandwidth_kbps INTEGER NOT NULL DEFAULT 0,
            duration_min INTEGER NOT NULL DEFAULT 60,
            description TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            note TEXT,
            group_name TEXT NOT NULL DEFAULT 'misafir',
            duration_min INTEGER NOT NULL DEFAULT 60,
            used INTEGER NOT NULL DEFAULT 0,
            used_by_ip TEXT, used_at TEXT, created TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity TEXT NOT NULL, method TEXT NOT NULL,
            group_name TEXT, ip TEXT, mac TEXT,
            bandwidth_kbps INTEGER DEFAULT 0,
            started TEXT NOT NULL, expires TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.commit()
    row = conn.execute("SELECT value FROM portal_settings WHERE key='enabled'").fetchone()
    if row is None:
        conn.execute("INSERT INTO portal_settings (key, value) VALUES ('enabled', '0')")
    defaults = [
        ("personel", "", 50000, 480, "Serbest erisim"),
        ("ogrenci", "adult,social,games", 10000, 120, "Sinirli erisim"),
        ("misafir", "adult,social,games,ads", 2000, 60, "En sinirli"),
    ]
    for name, cats, bw, dur, desc in defaults:
        conn.execute("INSERT OR IGNORE INTO portal_groups (name, categories, bandwidth_kbps, duration_min, description) VALUES (?, ?, ?, ?, ?)",
                     (name, cats, bw, dur, desc))
    conn.commit()
    conn.close()

def is_enabled():
    conn = get_conn()
    row = conn.execute("SELECT value FROM portal_settings WHERE key='enabled'").fetchone()
    conn.close()
    return row and row["value"] == "1"

def set_enabled(on):
    conn = get_conn()
    conn.execute("INSERT INTO portal_settings (key, value) VALUES ('enabled', ?) ON CONFLICT(key) DO UPDATE SET value=?",
                 ("1" if on else "0", "1" if on else "0"))
    conn.commit()
    conn.close()

def list_groups():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM portal_groups ORDER BY name").fetchall()
    conn.close()
    return rows

def get_group(name):
    conn = get_conn()
    row = conn.execute("SELECT * FROM portal_groups WHERE name=?", (name,)).fetchone()
    conn.close()
    return row

def create_group(name, bandwidth_kbps=0, duration_min=60, categories="", description=""):
    name = name.strip().lower().replace(" ", "_")
    if not name:
        return False, "Grup adi gerekli"
    conn = get_conn()
    try:
        conn.execute("INSERT INTO portal_groups (name, categories, bandwidth_kbps, duration_min, description) VALUES (?, ?, ?, ?, ?)",
                     (name, categories, int(bandwidth_kbps), int(duration_min), description))
        conn.commit()
        ok, msg = True, "Grup olusturuldu"
    except sqlite3.IntegrityError:
        ok, msg = False, "Bu grup adi zaten var"
    conn.close()
    return ok, msg

def update_group(name, categories, bandwidth_kbps, duration_min=None, max_devices=None):
    conn = get_conn()
    conn.execute("UPDATE portal_groups SET categories=?, bandwidth_kbps=? WHERE name=?",
                 (categories, int(bandwidth_kbps), name))
    if duration_min is not None:
        conn.execute("UPDATE portal_groups SET duration_min=? WHERE name=?", (int(duration_min), name))
    if max_devices is not None:
        conn.execute("UPDATE portal_groups SET max_devices=? WHERE name=?", (int(max_devices), name))
    conn.commit()
    conn.close()

def delete_group(name):
    conn = get_conn()
    conn.execute("DELETE FROM portal_groups WHERE name=?", (name,))
    conn.commit()
    conn.close()

def _hash(pw): return bcrypt.hashpw(pw.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")
def _verify(pw, h):
    try: return bcrypt.checkpw(pw.encode("utf-8")[:72], h.encode("utf-8"))
    except Exception: return False

def list_portal_users():
    conn = get_conn()
    rows = conn.execute("SELECT id, username, full_name, group_name, duration_min, bandwidth_kbps, enabled, created FROM portal_users ORDER BY id").fetchall()
    conn.close()
    return rows

def add_portal_user(username, password, full_name, group_name, duration_min, bandwidth_kbps=0, max_devices=0):
    username = username.strip()
    if not username or not password:
        return False, "Kullanici adi ve sifre gerekli"
    conn = get_conn()
    try:
        conn.execute("INSERT INTO portal_users (username, password_hash, full_name, group_name, duration_min, bandwidth_kbps, max_devices, enabled, created) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
                     (username, _hash(password), full_name.strip(), group_name, int(duration_min), int(bandwidth_kbps), int(max_devices), datetime.now().strftime("%Y-%m-%d %H:%M")))
        conn.commit()
        ok, msg = True, "Kullanici eklendi"
    except sqlite3.IntegrityError:
        ok, msg = False, "Bu kullanici adi zaten var"
    conn.close()
    return ok, msg

def delete_portal_user(uid):
    conn = get_conn()
    conn.execute("DELETE FROM portal_users WHERE id=?", (uid,))
    conn.commit()
    conn.close()

def generate_code(note, group_name, duration_min, count=1):
    conn = get_conn()
    created = []
    for _ in range(count):
        code = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        try:
            conn.execute("INSERT INTO portal_codes (code, note, group_name, duration_min, used, created) VALUES (?, ?, ?, ?, 0, ?)",
                         (code, note.strip(), group_name, int(duration_min), datetime.now().strftime("%Y-%m-%d %H:%M")))
            created.append(code)
        except sqlite3.IntegrityError:
            continue
    conn.commit()
    conn.close()
    return created

def list_codes():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM portal_codes ORDER BY id DESC").fetchall()
    conn.close()
    return rows

def delete_code(cid):
    conn = get_conn()
    conn.execute("DELETE FROM portal_codes WHERE id=?", (cid,))
    conn.commit()
    conn.close()

def _effective_bw(user_bw, group_name):
    if user_bw and user_bw > 0:
        return user_bw
    g = get_group(group_name)
    return g["bandwidth_kbps"] if g else 0


def _effective_max_devices(user_max, group_name):
    """Kisi limiti 0 ise grup limitini kullan."""
    if user_max and user_max > 0:
        return user_max
    g = get_group(group_name)
    return g["max_devices"] if g and "max_devices" in g.keys() else 1

def _device_name(mac):
    """DHCP lease dosyasindan MAC'in cihaz ismini bulur."""
    if not mac:
        return ""
    try:
        with open("/var/lib/misc/dnsmasq.leases") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[1].lower() == mac.lower():
                    name = parts[3]
                    return name if name != "*" else ""
    except Exception:
        pass
    return ""

def active_sessions_for(identity):
    """Bir kullanicinin aktif oturumlarini dondurur (ayni identity)."""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM portal_sessions WHERE identity=? AND active=1 ORDER BY started", (identity,)).fetchall()
    conn.close()
    return rows

def close_session_with_password(session_id, identity, password):
    """Kullanici sifresiyle kendi oturumunu kapatir."""
    conn = get_conn()
    u = conn.execute("SELECT * FROM portal_users WHERE username=? AND enabled=1", (identity,)).fetchone()
    conn.close()
    if not u or not _verify(password, u["password_hash"]):
        return False, "Sifre hatali"
    # Oturum bu kullaniciya mi ait?
    conn = get_conn()
    s = conn.execute("SELECT * FROM portal_sessions WHERE id=? AND identity=? AND active=1", (session_id, identity)).fetchone()
    conn.close()
    if not s:
        return False, "Oturum bulunamadi"
    end_session(session_id)
    return True, "Oturum kapatildi"

def portal_login(identity, secret, ip="", mac=""):
    conn = get_conn()
    duration = method = ident = group = None
    bw = 0
    row = conn.execute("SELECT * FROM portal_codes WHERE code=?", (secret.strip().upper(),)).fetchone()
    if row and not identity.strip():
        if row["used"]:
            conn.close()
            return False, "Bu kod zaten kullanilmis"
        duration, method, ident, group = row["duration_min"], "kod", f"kod:{row['code']}", row["group_name"]
        conn.execute("UPDATE portal_codes SET used=1, used_by_ip=?, used_at=? WHERE id=?",
                     (ip, datetime.now().strftime("%Y-%m-%d %H:%M"), row["id"]))
    else:
        u = conn.execute("SELECT * FROM portal_users WHERE username=? AND enabled=1", (identity.strip(),)).fetchone()
        if u and _verify(secret, u["password_hash"]):
            duration, method, ident, group, bw = u["duration_min"], "hesap", u["username"], u["group_name"], u["bandwidth_kbps"]
            user_max = u["max_devices"] if "max_devices" in u.keys() else 0
        else:
            conn.close()
            return False, "Kullanici adi/sifre veya kod hatali"
    conn.close()
    # --- Cihaz limiti kontrolu (sadece hesap girisinde) ---
    if method == "hesap":
        umax = user_max if 'user_max' in dir() else 0
        limit = _effective_max_devices(umax, group)
        actives = active_sessions_for(ident)
        # Bu cihaz (MAC) zaten acik mi? Ayni cihaz tekrar giriyorsa sorun yok
        this_mac_active = any(s["mac"] and mac and s["mac"].lower() == mac.lower() for s in actives)
        if not this_mac_active and len(actives) >= limit:
            # Limit dolu - aktif oturumlari isaretle dondur
            dev_list = "|".join(f"{s['id']},{s['mac'] or '?'},{s['ip'] or '?'},{s['started']},{_device_name(s['mac']) or 'Bilinmeyen cihaz'}" for s in actives)
            return "LIMIT", f"{ident}||{limit}||{dev_list}"
    eff_bw = _effective_bw(bw, group)
    now = datetime.now()
    expires = now + timedelta(minutes=duration)
    conn = get_conn()
    conn.execute("INSERT INTO portal_sessions (identity, method, group_name, ip, mac, bandwidth_kbps, started, expires, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
                 (ident, method, group, ip, mac, eff_bw, now.strftime("%Y-%m-%d %H:%M"), expires.strftime("%Y-%m-%d %H:%M")))
    conn.commit()
    conn.close()
    try:
        from app import gateway
        gateway.on_login(ip, mac, group, eff_bw)
    except Exception:
        pass
    bw_txt = f"{eff_bw//1000} Mbps" if eff_bw else "sinirsiz"
    return True, f"Giris basarili ({group} grubu, {duration} dk, {bw_txt})"

def list_sessions(active_only=True):
    conn = get_conn()
    if active_only:
        rows = conn.execute("SELECT * FROM portal_sessions WHERE active=1 ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM portal_sessions ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return rows

def end_session(sid):
    conn = get_conn()
    row = conn.execute("SELECT ip, mac FROM portal_sessions WHERE id=?", (sid,)).fetchone()
    conn.execute("UPDATE portal_sessions SET active=0 WHERE id=?", (sid,))
    conn.commit()
    conn.close()
    if row:
        try:
            from app import gateway
            gateway.on_logout(row["ip"], row["mac"])
        except Exception:
            pass
