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

LOG_DIR = "/var/log/netgate5651"

def _read_lines(date_from=None, date_to=None, max_lines=2000000):
    """Tarih araligindaki gunluk dosyalari okur. Bos ise tum gunler + eski arsiv."""
    from datetime import datetime, timedelta
    import os, glob
    lines = []
    # 1) Eski tek-dosya sistemi (gecmis veri) - sadece tarih araligi genisse ya da bossa
    #    Eski veriler tek dosyada, gunu ayirt edemedigimiz icin dahil ediyoruz
    for p in ("/var/log/netgate-5651.log.1", "/var/log/netgate-5651.log"):
        try:
            with open(p, "r", errors="ignore") as f:
                lines.extend(f.read().splitlines())
        except Exception:
            pass
    # 2) Gunluk dosyalar - tarih araligina gore
    if date_from and date_to:
        try:
            d = datetime.strptime(date_from, "%Y-%m-%d")
            dt_end = datetime.strptime(date_to, "%Y-%m-%d")
            while d <= dt_end:
                fp = f"{LOG_DIR}/{d.strftime('%Y-%m-%d')}.log"
                try:
                    with open(fp, "r", errors="ignore") as f:
                        lines.extend(f.read().splitlines())
                except Exception:
                    pass
                d += timedelta(days=1)
        except Exception:
            pass
    else:
        # Tarih yoksa tum gunluk dosyalari oku
        for fp in sorted(glob.glob(f"{LOG_DIR}/*.log")):
            try:
                with open(fp, "r", errors="ignore") as f:
                    lines.extend(f.read().splitlines())
            except Exception:
                pass
    return lines[-max_lines:]

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

    for line in _read_lines(date_from, date_to):
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
