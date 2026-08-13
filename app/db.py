import sqlite3
import pathlib
from datetime import datetime

DB_PATH = pathlib.Path(__file__).parent.parent / "data" / "netgate.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Uygulama acilirken tablolari olusturur (yoksa)."""
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

def add_domain(domain: str, note: str = ""):
    domain = domain.strip().lower()
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO blocked_domains (domain, note, created) VALUES (?, ?, ?)",
            (domain, note.strip(), datetime.now().strftime("%Y-%m-%d %H:%M"))
        )
        conn.commit()
        ok = True
    except sqlite3.IntegrityError:
        ok = False  # zaten listede
    conn.close()
    return ok

def delete_domain(domain_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM blocked_domains WHERE id = ?", (domain_id,))
    conn.commit()
    conn.close()