import sqlite3
import secrets
import string
from datetime import datetime, timedelta
from app.db import get_conn
import bcrypt

# ---------- Kurulum ----------

def init_portal():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name     TEXT,
            group_name    TEXT NOT NULL DEFAULT 'ogrenci',
            duration_min  INTEGER NOT NULL DEFAULT 60,
            enabled       INTEGER NOT NULL DEFAULT 1,
            created       TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_groups (
            name        TEXT PRIMARY KEY,
            categories  TEXT,
            description TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_codes (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            code         TEXT UNIQUE NOT NULL,
            note         TEXT,
            group_name   TEXT NOT NULL DEFAULT 'misafir',
            duration_min INTEGER NOT NULL DEFAULT 60,
            used         INTEGER NOT NULL DEFAULT 0,
            used_by_ip   TEXT,
            used_at      TEXT,
            created      TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portal_sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            identity    TEXT NOT NULL,
            method      TEXT NOT NULL,
            group_name  TEXT,
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
    # Varsayilan gruplar
    defaults = [
        ("personel", "", "Serbest erisim - sadece zararli/reklam engeli"),
        ("ogrenci", "adult,social,games", "Sinirli - yetiskin, sosyal medya, oyun engeli"),
        ("misafir", "adult,social,games,ads", "En sinirli - tum kategoriler engeli"),
    ]
    for name, cats, desc in defaults:
        conn.execute("INSERT OR IGNORE INTO portal_groups (name, categories, description) VALUES (?, ?, ?)",
                     (name, cats, desc))
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

# ---------- Gruplar ----------

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

def update_group(name, categories):
    conn = get_conn()
    conn.execute("UPDATE portal_groups SET categories=? WHERE name=?", (categories, name))
    conn.commit()
    conn.close()

# ---------- Kalici kullanicilar ----------

def _hash(pw): return bcrypt.hashpw(pw.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")
def _verify(pw, h):
    try: return bcrypt.checkpw(pw.encode("utf-8")[:72], h.encode("utf-8"))
    except Exception: return False

def list_portal_users():
    conn = get_conn()
    rows = conn.execute("SELECT id, username, full_name, group_name, duration_min, enabled, created FROM portal_users ORDER BY id").fetchall()
    conn.close()
    return rows

def add_portal_user(username, password, full_name, group_name, duration_min):
    username = username.strip()
    if not username or not password:
        return False, "Kullanici adi ve sifre gerekli"
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO portal_users (username, password_hash, full_name, group_name, duration_min, enabled, created) VALUES (?, ?, ?, ?, ?, 1, ?)",
            (username, _hash(password), full_name.strip(), group_name, int(duration_min), datetime.now().strftime("%Y-%m-%d %H:%M"))
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

def generate_code(note, group_name, duration_min, count=1):
    conn = get_conn()
    created = []
    for _ in range(count):
        code = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        try:
            conn.execute(
                "INSERT INTO portal_codes (code, note, group_name, duration_min, used, created) VALUES (?, ?, ?, ?, 0, ?)",
                (code, note.strip(), group_name, int(duration_min), datetime.now().strftime("%Y-%m-%d %H:%M"))
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

# ---------- Giris dogrulama ----------

def portal_login(identity, secret, ip="", mac=""):
    conn = get_conn()
    duration = None
    method = None
    ident = None
    group = None

    row = conn.execute("SELECT * FROM portal_codes WHERE code=?", (secret.strip().upper(),)).fetchone()
    if row and not identity.strip():
        if row["used"]:
            conn.close()
            return False, "Bu kod zaten kullanilmis"
        duration = row["duration_min"]
        method = "kod"
        ident = f"kod:{row['code']}"
        group = row["group_name"]
        conn.execute("UPDATE portal_codes SET used=1, used_by_ip=?, used_at=? WHERE id=?",
                     (ip, datetime.now().strftime("%Y-%m-%d %H:%M"), row["id"]))
    else:
        u = conn.execute("SELECT * FROM portal_users WHERE username=? AND enabled=1", (identity.strip(),)).fetchone()
        if u and _verify(secret, u["password_hash"]):
            duration = u["duration_min"]
            method = "hesap"
            ident = u["username"]
            group = u["group_name"]
        else:
            conn.close()
            return False, "Kullanici adi/sifre veya kod hatali"

    now = datetime.now()
    expires = now + timedelta(minutes=duration)
    conn.execute(
        "INSERT INTO portal_sessions (identity, method, group_name, ip, mac, started, expires, active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
        (ident, method, group, ip, mac, now.strftime("%Y-%m-%d %H:%M"), expires.strftime("%Y-%m-%d %H:%M"))
    )
    conn.commit()
    conn.close()
    return True, f"Giris basarili ({group} grubu, {duration} dakika)"

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