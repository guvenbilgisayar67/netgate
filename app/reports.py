"""NetGate - Kullanici bazli raporlama (5651 logundan)"""
import subprocess
from collections import defaultdict
from datetime import datetime

LOG_5651 = "/var/log/netgate-5651.log"

MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
          "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}

def _parse_time(ts):
    """'Aug 15 12:42:36' -> datetime (yil = bu yil)"""
    try:
        parts = ts.split()
        month = MONTHS.get(parts[0], 1)
        day = int(parts[1])
        h, m, s = parts[2].split(":")
        return datetime(datetime.now().year, month, day, int(h), int(m), int(s))
    except Exception:
        return None

def _read_lines(max_lines=200000):
    try:
        out = subprocess.run(["sudo", "tail", "-n", str(max_lines), LOG_5651],
                             capture_output=True, text=True, timeout=15).stdout
        return out.splitlines()
    except Exception:
        return []

def _user_lookup():
    """Kullanici adi -> ad soyad eslemesi (arama icin)."""
    from app.db import get_conn
    m = {}
    try:
        conn = get_conn()
        for r in conn.execute("SELECT username, full_name FROM portal_users").fetchall():
            m[r["username"]] = r["full_name"] or ""
        conn.close()
    except Exception:
        pass
    return m

def search_user_activity(query="", date_from=None, date_to=None, limit=500):
    """
    query: kullanici adi, ad-soyad veya MAC/cihaz adi (bos = herkes)
    date_from/date_to: 'YYYY-MM-DD' string ya da None
    Doner: {users: [...ozet...], details: [...satirlar...]}
    """
    query = (query or "").strip().lower()
    users_fullname = _user_lookup()

    df = datetime.strptime(date_from, "%Y-%m-%d") if date_from else None
    dt = datetime.strptime(date_to + " 23:59:59", "%Y-%m-%d %H:%M:%S") if date_to else None

    # kullanici -> {siteler: {domain: count}, ilk, son, toplam_sorgu, mac}
    stats = defaultdict(lambda: {"sites": defaultdict(int), "first": None, "last": None,
                                  "total": 0, "macs": set(), "fullname": ""})
    details = []

    for line in _read_lines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        ts, user, mac, ip, domain = parts[0], parts[1], parts[2], parts[3], parts[4]
        dt_obj = _parse_time(ts)
        if df and dt_obj and dt_obj < df:
            continue
        if dt and dt_obj and dt_obj > dt:
            continue

        fullname = users_fullname.get(user, "")
        # Arama filtresi: kullanici adi, ad-soyad veya mac
        if query:
            hay = f"{user} {fullname} {mac}".lower()
            if query not in hay:
                continue

        s = stats[user]
        s["fullname"] = fullname
        s["sites"][domain] += 1
        s["total"] += 1
        if mac and mac not in ("?", "giris-yok"):
            s["macs"].add(mac)
        if s["first"] is None or (dt_obj and dt_obj < s["first"]):
            s["first"] = dt_obj
        if s["last"] is None or (dt_obj and dt_obj > s["last"]):
            s["last"] = dt_obj

        if len(details) < limit:
            details.append({"time": ts, "user": user, "fullname": fullname,
                            "mac": mac, "ip": ip, "domain": domain})

    # Ozet listesi
    users = []
    for user, s in stats.items():
        top_sites = sorted(s["sites"].items(), key=lambda x: -x[1])[:10]
        users.append({
            "user": user,
            "fullname": s["fullname"],
            "total": s["total"],
            "unique_sites": len(s["sites"]),
            "macs": ", ".join(sorted(s["macs"])) if s["macs"] else "-",
            "first": s["first"].strftime("%Y-%m-%d %H:%M") if s["first"] else "-",
            "last": s["last"].strftime("%Y-%m-%d %H:%M") if s["last"] else "-",
            "top_sites": top_sites,
        })
    users.sort(key=lambda x: -x["total"])
    details.reverse()  # en yeni ustte
    return {"users": users, "details": details[:limit]}
