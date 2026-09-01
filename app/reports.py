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


def dashboard_stats(gun_sayisi=1):
    """Dashboard grafikleri icin istatistik: en cok siteler, saatlik dagilim, en aktif kullanicilar."""
    from datetime import datetime, timedelta
    from collections import defaultdict, Counter
    # Bugunun (ya da son N gun) tarih araligi
    bugun = datetime.now()
    date_from = (bugun - timedelta(days=gun_sayisi-1)).strftime("%Y-%m-%d")
    date_to = bugun.strftime("%Y-%m-%d")
    lines = _read_lines(date_from, date_to)

    site_counter = Counter()
    user_counter = Counter()
    saat_counter = defaultdict(int)
    toplam = 0
    tekil_kullanici = set()
    tekil_cihaz = set()

    for line in lines:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        ts, user, mac, ip, domain = parts[0], parts[1], parts[2], parts[3], parts[4]
        dt = _parse_time(ts)
        # Tarih filtresi (gunluk dosyalar + eski tek-dosya karisik olabilir)
        if dt:
            gun_str = dt.strftime("%Y-%m-%d")
            if gun_str < date_from or gun_str > date_to:
                continue
        # Domain'i sadelestir (www. at, alt alan adlarini kok domaine indirge basit)
        d = domain.lower().replace("www.", "")
        # Sistem/gurultu domainlerini atla (daha anlamli grafik)
        GURULTU = ["msftconnecttest", "msftncsi", "in-addr.arpa", "windowsupdate",
                   "gvt1.com", "ntp.org", "edge.skype", "data.microsoft",
                   "settings-win", "dns.google", "ocsp", "crl.", "push.apple",
                   "safebrowsing", "connectivitycheck", "clients.google"]
        if any(x in d for x in GURULTU):
            continue  # gurultu - grafige katma
        site_counter[d] += 1
        if user and user != "giris-yok":
            user_counter[user] += 1
            tekil_kullanici.add(user)
        if mac and mac not in ("?", "giris-yok"):
            tekil_cihaz.add(mac)
        if dt:
            saat_counter[dt.hour] += 1
        toplam += 1

    # Saatlik dagilim (0-23)
    saatlik = [saat_counter.get(h, 0) for h in range(24)]

    return {
        "top_sites": site_counter.most_common(10),
        "top_users": user_counter.most_common(10),
        "saatlik": saatlik,
        "toplam_erisim": toplam,
        "tekil_kullanici": len(tekil_kullanici),
        "tekil_cihaz": len(tekil_cihaz),
    }


def dashboard_extra():
    """Ek grafikler: gunluk trend (7 gun), kategori dagilimi, engellenen istekler."""
    from datetime import datetime, timedelta
    from collections import Counter
    import glob, os, subprocess

    # 1) GUNLUK TREND - son 7 gunun erisim sayisi
    gunluk_trend = []
    bugun = datetime.now()
    for i in range(6, -1, -1):
        gun = (bugun - timedelta(days=i))
        gun_str = gun.strftime("%Y-%m-%d")
        fp = f"{LOG_DIR}/{gun_str}.log"
        sayi = 0
        try:
            with open(fp, "r", errors="ignore") as f:
                sayi = sum(1 for _ in f)
        except Exception:
            sayi = 0
        gunluk_trend.append({"gun": gun.strftime("%d.%m"), "sayi": sayi})

    # 2) KATEGORI DAGILIMI - bugunku trafigi kategorilere ayir
    kat_domainleri = {
        "Sosyal Medya": ["youtube", "instagram", "tiktok", "facebook", "twitter", "x.com", "snapchat", "reddit", "whatsapp", "telegram"],
        "Oyun": ["steampowered", "epicgames", "roblox", "twitch", "ea.com", "battle.net", "minecraft", "riotgames"],
        "Video/Muzik": ["netflix", "spotify", "disney", "twitch", "vimeo", "dailymotion"],
        "Arama/Genel": ["google", "bing", "yahoo", "yandex", "duckduckgo"],
    }
    kat_sayac = Counter()
    lines_today = _read_lines(bugun.strftime("%Y-%m-%d"), bugun.strftime("%Y-%m-%d"))
    for line in lines_today:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        d = parts[4].lower()
        bulundu = False
        for kat, domainler in kat_domainleri.items():
            if any(dom in d for dom in domainler):
                kat_sayac[kat] += 1
                bulundu = True
                break
        if not bulundu:
            kat_sayac["Diger"] += 1

    # 3) ENGELLENEN ISTEKLER - DNS logundan (0.0.0.0 donenler)
    engellenen_sayi = 0
    engellenen_siteler = Counter()
    try:
        out = subprocess.run(["tail", "-n", "50000", "/var/log/netgate-dns.log"],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            if " is 0.0.0.0" in line or " is ::" in line:
                # ornek: ... config example.com is 0.0.0.0
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "is" and i > 0:
                        dom = parts[i-1].replace("www.", "")
                        engellenen_siteler[dom] += 1
                        engellenen_sayi += 1
                        break
    except Exception:
        pass

    return {
        "gunluk_trend": gunluk_trend,
        "kategori": dict(kat_sayac),
        "engellenen_sayi": engellenen_sayi,
        "engellenen_top": engellenen_siteler.most_common(8),
    }
