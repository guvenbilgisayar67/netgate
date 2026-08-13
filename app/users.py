import sqlite3
import bcrypt
from datetime import datetime
from app.db import get_conn, DB_PATH

def _hash(password: str) -> str:
    # bcrypt 72 byte siniri: uzun sifreleri kirp
    pw = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")

def _verify(password: str, hashed: str) -> bool:
    try:
        pw = password.encode("utf-8")[:72]
        return bcrypt.checkpw(pw, hashed.encode("utf-8"))
    except Exception:
        return False

def init_users():
    """Kullanici tablosunu olusturur ve ilk admin yoksa varsayilan olusturur."""
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            must_change   INTEGER NOT NULL DEFAULT 0,
            created       TEXT NOT NULL
        )
    """)
    conn.commit()
    row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    if row["c"] == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, must_change, created) VALUES (?, ?, 1, ?)",
            ("admin", _hash("admin"), datetime.now().strftime("%Y-%m-%d %H:%M"))
        )
        conn.commit()
    conn.close()

def verify_user(username: str, password: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
    conn.close()
    if row and _verify(password, row["password_hash"]):
        return row
    return None

def list_users():
    conn = get_conn()
    rows = conn.execute("SELECT id, username, must_change, created FROM users ORDER BY id").fetchall()
    conn.close()
    return rows

def add_user(username: str, password: str):
    username = username.strip()
    if not username or not password:
        return False, "Kullanici adi ve sifre bos olamaz"
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, must_change, created) VALUES (?, ?, 0, ?)",
            (username, _hash(password), datetime.now().strftime("%Y-%m-%d %H:%M"))
        )
        conn.commit()
        ok, msg = True, "Kullanici eklendi"
    except sqlite3.IntegrityError:
        ok, msg = False, "Bu kullanici adi zaten var"
    conn.close()
    return ok, msg

def change_password(username: str, new_password: str):
    if not new_password or len(new_password) < 4:
        return False, "Sifre en az 4 karakter olmali"
    conn = get_conn()
    conn.execute(
        "UPDATE users SET password_hash = ?, must_change = 0 WHERE username = ?",
        (_hash(new_password), username)
    )
    conn.commit()
    conn.close()
    return True, "Sifre guncellendi"

def delete_user(user_id: int):
    conn = get_conn()
    cnt = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if cnt <= 1:
        conn.close()
        return False, "Son yonetici silinemez"
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return True, "Kullanici silindi"