import subprocess
from datetime import datetime

LOG_FILE = "/var/log/netgate-dns.log"
LOG_5651 = "/var/log/netgate-5651.log"

def read_dns_logs(limit: int = 200, only_blocked: bool = False, search: str = ""):
    """5651 birlesik logunu okur. Format: zaman | kullanici | mac | ip | site"""
    try:
        import glob as _glob
        _lines = []
        # En yeni gunluk dosyalar (son 3 gun yeterli - loglar sayfasi guncel kayitlar icin)
        _daily = sorted(_glob.glob("/var/log/netgate5651/*.log"))[-3:]
        # Eski tek-dosya da dahil (gecmis, gunluk dosya yoksa)
        _sources = ["/var/log/netgate-5651.log"] + _daily if not _daily else _daily
        for _p in _sources:
            try:
                with open(_p, "r", errors="ignore") as _f:
                    _lines.extend(_f.read().splitlines())
            except Exception:
                pass
        out = "\n".join(_lines[-(limit * 3):])
    except Exception:
        return []
    results = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        zaman, kullanici, mac, ip, domain = parts[0], parts[1], parts[2], parts[3], parts[4]
        results.append({
            "time": zaman,
            "user": kullanici,
            "mac": mac,
            "client": ip,
            "domain": domain,
            "blocked": False,
        })
    results.reverse()  # en yeni ustte
    if search:
        s = search.lower()
        results = [r for r in results if s in r["domain"].lower() or s in r["client"] or s in r["user"].lower() or s in r["mac"].lower()]
    return results[:limit]

def log_stats():
    """Ozet: toplam sorgu, engellenen sayisi."""
    logs = read_dns_logs(limit=1000)
    total = len(logs)
    blocked = sum(1 for r in logs if r["blocked"])
    return {"total": total, "blocked": blocked, "allowed": total - blocked}