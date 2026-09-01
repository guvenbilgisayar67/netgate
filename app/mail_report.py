#!/usr/bin/env python3
"""NetGate - Gunluk log raporunu Excel olarak mail atar (her aksam)."""
import sys, os, smtplib, ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import io

sys.path.insert(0, "/home/yasin/netgate")

LOG_DIR = "/var/log/netgate5651"
CONF = "/etc/netgate/mail.conf"

def read_conf():
    cfg = {}
    try:
        with open(CONF) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    except Exception as e:
        print("mail.conf okunamadi:", e)
    return cfg

def _gun_listesi(period):
    """Periyoda gore hangi gunlerin logu alinacak (tarih string listesi)."""
    from datetime import datetime, timedelta
    bugun = datetime.now()
    if period == "weekly":
        # Son 7 gun (bugun dahil)
        return [(bugun - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
    elif period == "monthly":
        # Bu ayin 1'inden bugune
        gunler = []
        d = bugun.replace(day=1)
        while d <= bugun:
            gunler.append(d.strftime("%Y-%m-%d"))
            d += timedelta(days=1)
        return gunler
    else:  # daily
        return [bugun.strftime("%Y-%m-%d")]

def build_excel(period="daily"):
    """Periyoda gore log(lar)i Excel olarak olustur, bytes dondur."""
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "5651 Log"
    ws.append(["Zaman", "Kullanici", "MAC", "IP", "Site"])
    satir = 0
    for gun_str in _gun_listesi(period):
        fp = f"{LOG_DIR}/{gun_str}.log"
        try:
            with open(fp, "r", errors="ignore") as f:
                for line in f:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 5:
                        ws.append(parts[:5])
                        satir += 1
        except FileNotFoundError:
            pass
    for col, w in zip("ABCDE", [20, 20, 20, 16, 40]):
        ws.column_dimensions[col].width = w
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.read(), satir

def main():
    cfg = read_conf()
    # Ayarlar dolu mu kontrol
    if not cfg.get("SMTP_USER") or "GONDEREN" in cfg.get("SMTP_USER", "") or not cfg.get("MAIL_TO") or "ALICI" in cfg.get("MAIL_TO", ""):
        print("mail.conf henuz doldurulmamis - gonderim atlandi")
        return
    from datetime import datetime, timedelta
    period = cfg.get("PERIOD", "daily").strip().lower()
    bugun = datetime.now()
    # Periyoda gore gonderme gunu kontrolu
    if period == "weekly" and bugun.weekday() != 6:  # 6 = Pazar
        print("Haftalik rapor - bugun Pazar degil, atlandi")
        return
    if period == "monthly":
        yarin = bugun + timedelta(days=1)
        if yarin.day != 1:  # ayin son gunu degil
            print("Aylik rapor - bugun ayin son gunu degil, atlandi")
            return
    gun_str = bugun.strftime("%Y-%m-%d")
    excel_data, satir = build_excel(period)
    period_ad = {"daily": "Gunluk", "weekly": "Haftalik", "monthly": "Aylik"}.get(period, "Gunluk")

    msg = MIMEMultipart()
    msg["From"] = cfg["SMTP_USER"]
    msg["To"] = cfg["MAIL_TO"]
    msg["Subject"] = f"NetGate 5651 {period_ad} Log Raporu - {gun_str} ({satir} kayit)"
    govde = f"Merhaba,\n\n{gun_str} tarihli internet erisim logu ektedir.\nToplam {satir} kayit.\n\nNetGate Otomatik Rapor"
    msg.attach(MIMEText(govde, "plain"))

    part = MIMEBase("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    part.set_payload(excel_data)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="netgate-{period}-log-{gun_str}.xlsx"')
    msg.attach(part)

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(cfg["SMTP_SERVER"], int(cfg.get("SMTP_PORT", 587))) as server:
            server.starttls(context=ctx)
            server.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
            # Birden fazla alici (virgulle ayrilmis) destekle
            aliciler = [a.strip() for a in cfg["MAIL_TO"].split(",") if a.strip()]
            server.sendmail(cfg["SMTP_USER"], aliciler, msg.as_string())
        print(f"Mail gonderildi: {cfg['MAIL_TO']} ({satir} kayit, {gun_str})")
    except Exception as e:
        print("Mail gonderilemedi:", e)

if __name__ == "__main__":
    main()
