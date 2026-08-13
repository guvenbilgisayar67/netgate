import sqlite3
import secrets
import string
from datetime import datetime, timedelta
from app.db import get_conn
import bcrypt

# ---------- Kurulum ----------

def init_portal():
    conn = get_conn()
    # Portal ayarlari (acik/kapali)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    # Kalici kullanici hesaplari (personel, ogrenci)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name     TEXT,
            duration_min  INTEGER NOT NULL DEFAULT 60,
            enabled       INTEGER NOT NULL DEFAULT 1,
            created       TEXT NOT NULL
        )
    """)
    # Tek kullanimlik / misafir kodlari
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_codes (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            code         TEXT UNIQUE NOT NULL,
            note         TEXT,
            duration_min INTEGER NOT NULL DEFAULT 60,
            used         INTEGER NOT NULL DEFAULT 0,
            used_by_ip   TEXT,
            used_at      TEXT,
            created      TEXT NOT NULL
        )
    """)
    # Aktif oturumlar (5651: kim, hangi IP/MAC, ne zaman)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            identity    TEXT NOT NULL,
            method      TEXT NOT NULL,
            ip          TEXT,
            mac         TEXT,
            started     TEXT NOT NULL,
            expires     TEXT NOT NULL,
            active      INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.commit()
    # Varsayilan: portal kapali
    row = conn.execute("SELECT value FROM portal_settings WHERE key='enabled'").fetchone()
    if row is None:
        conn.execute("INSERT INTO portal_settings (key, value) VALUES ('enabled', '0')")
        conn.commit()
    conn.close()

# ---------- Ayarlar ----------

def is_enabled():
    conn = get_conn()
    row = conn.execute("SELECT value FROM portal_settings WHERE key='enabled'").fetchone()
    conn.close()
    return row and row["value"] == "1"

def set_enabled(on: bool):
    conn = get_conn()
    conn.execute("INSERT INTO portal_settings (key, value) VALUES ('enabled', ?) "
                 "ON CONFLICT(key) DO UPDATE SET value=?", ("1" if on else "0", "1" if on else "0"))
    conn.commit()
    conn.close()

# ---------- Kalici kullanicilar ----------

def _hash(pw): return bcrypt.hashpw(pw.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")
def _verify(pw, h):
    try: return bcrypt.checkpw(pw.encode("utf-8")[:72], h.encode("utf-8"))
    except Exception: return False

def list_portal_users():
    conn = get_conn()
    rows = conn.execute("SELECT id, username, full_name, duration_min, enabled, created FROM portal_users ORDER BY id").fetchall()
    conn.close()
    return rows

def add_portal_user(username, password, full_name, duration_min):
    username = username.strip()
    if not username or not password:
        return False, "Kullanici adi ve sifre gerekli"
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO portal_users (username, password_hash, full_name, duration_min, enabled, created) VALUES (?, ?, ?, ?, 1, ?)",
            (username, _hash(password), full_name.strip(), int(duration_min), datetime.now().strftime("%Y-%m-%d %H:%M"))
        )
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

# ---------- Misafir kodlari ----------

def generate_code(note, duration_min, count=1):
    conn = get_conn()
    created = []
    for _ in range(count):
        code = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        try:
            conn.execute(
                "INSERT INTO portal_codes (code, note, duration_min, used, created) VALUES (?, ?, ?, 0, ?)",
                (code, note.strip(), int(duration_min), datetime.now().strftime("%Y-%m-%d %H:%M"))
            )
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

# ---------- Giris dogrulama (portal'dan gelen) ----------

def portal_login(identity, secret, ip="", mac=""):
    """Kullanici adi/sifre VEYA kod ile giris. Basarili olursa oturum acar."""
    conn = get_conn()
    duration = None
    method = None
    ident = None

    # Once kod mu diye bak (6 haneli buyuk harf/rakam)
    row = conn.execute("SELECT * FROM portal_codes WHERE code=?", (secret.strip().upper(),)).fetchone()
    if row and not identity.strip():
        if row["used"]:
            conn.close()
            return False, "Bu kod zaten kullanilmis"
        duration = row["duration_min"]
        method = "kod"
        ident = f"kod:{row['code']}"
        conn.execute("UPDATE portal_codes SET used=1, used_by_ip=?, used_at=? WHERE id=?",
                     (ip, datetime.now().strftime("%Y-%m-%d %H:%M"), row["id"]))
    else:
        # Kullanici adi/sifre
        u = conn.execute("SELECT * FROM portal_users WHERE username=? AND enabled=1", (identity.strip(),)).fetchone()
        if u and _verify(secret, u["password_hash"]):
            duration = u["duration_min"]
            method = "hesap"
            ident = u["username"]
        else:
            conn.close()
            return False, "Kullanici adi/sifre veya kod hatali"

    # Oturum olustur
    now = datetime.now()
    expires = now + timedelta(minutes=duration)
    conn.execute(
        "INSERT INTO portal_sessions (identity, method, ip, mac, started, expires, active) VALUES (?, ?, ?, ?, ?, ?, 1)",
        (ident, method, ip, mac, now.strftime("%Y-%m-%d %H:%M"), expires.strftime("%Y-%m-%d %H:%M"))
    )
    conn.commit()
    conn.close()
    return True, f"Giris basarili ({duration} dakika)"

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
    conn.execute("UPDATE portal_sessions SET active=0 WHERE id=?", (sid,))
    conn.commit()
    conn.close()