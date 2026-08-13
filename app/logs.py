import subprocess
from datetime import datetime

LOG_FILE = "/var/log/netgate-dns.log"

def read_dns_logs(limit: int = 200, only_blocked: bool = False, search: str = ""):
    """dnsmasq log dosyasini okuyup yapilandirilmis kayitlara cevirir.
    Her kayit: zaman, istemci IP, alan adi, durum (izin/engel)."""
    try:
        # Dosyayi sudo ile oku (izin gerekebilir), son N*5 satiri al
        out = subprocess.run(
            ["sudo", "tail", "-n", str(limit * 6), LOG_FILE],
            capture_output=True, text=True, timeout=5
        ).stdout
    except Exception:
        return []

    # Once query satirlarini topla (kim neyi sordu), sonra sonuc satirlariyla esle
    queries = {}   # (domain) -> {time, client}
    results = []

    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        # Ornek: Aug 13 12:39:41 dnsmasq[23024]: query[A] bunlareve.com from 127.0.0.1
        try:
            zaman = " ".join(parts[0:3])
            if "query[" in line and " from " in line:
                domain = parts[5]
                client = parts[7]
                queries[domain] = {"time": zaman, "client": client}
            elif " is " in line and ("config " in line or "reply " in line or "cached " in line):
                # config X is 0.0.0.0  -> engel ;  reply/cached X is <ip> -> izin
                domain = parts[5]
                deger = parts[-1]
                blocked = deger in ("0.0.0.0", "::")
                q = queries.get(domain, {"time": zaman, "client": "-"})
                results.append({
                    "time": q["time"],
                    "client": q["client"],
                    "domain": domain,
                    "blocked": blocked,
                })
        except (IndexError, ValueError):
            continue

    # En yeni ustte
    results.reverse()

    # Filtreler
    if only_blocked:
        results = [r for r in results if r["blocked"]]
    if search:
        s = search.lower()
        results = [r for r in results if s in r["domain"].lower() or s in r["client"]]

    return results[:limit]

def log_stats():
    """Ozet: toplam sorgu, engellenen sayisi."""
    logs = read_dns_logs(limit=1000)
    total = len(logs)
    blocked = sum(1 for r in logs if r["blocked"])
    return {"total": total, "blocked": blocked, "allowed": total - blocked}