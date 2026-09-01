"""NetGate - Mail ayarlari okuma/yazma (panel icin)"""
import subprocess

CONF = "/etc/netgate/mail.conf"

def read_mail_conf():
    cfg = {"SMTP_SERVER": "smtp.gmail.com", "SMTP_PORT": "587",
           "SMTP_USER": "", "SMTP_PASSWORD": "", "MAIL_TO": "", "PERIOD": "daily"}
    try:
        with open(CONF) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip()
                    # Sablon degerlerini bos goster
                    if "GONDEREN" in v or "UYGULAMA_SIFRESI" in v or "ALICI" in v:
                        v = ""
                    cfg[k] = v
    except Exception:
        pass
    return cfg

def save_mail_conf(smtp_user, smtp_password, mail_to, period="daily", smtp_server="smtp.gmail.com", smtp_port="587"):
    icerik = f"""# NetGate mail ayarlari (panelden guncellendi)
SMTP_SERVER={smtp_server}
SMTP_PORT={smtp_port}
SMTP_USER={smtp_user.strip()}
SMTP_PASSWORD={smtp_password.strip()}
MAIL_TO={mail_to.strip()}
PERIOD={period.strip()}
"""
    # sudo ile yaz (root sahipli olabilir) - tee kullan
    try:
        p = subprocess.run(["sudo", "tee", CONF], input=icerik, capture_output=True, text=True, timeout=5)
        subprocess.run(["sudo", "chmod", "600", CONF], timeout=5)
        subprocess.run(["sudo", "chown", "yasin", CONF], timeout=5)
        return True, "Mail ayarlari kaydedildi"
    except Exception as e:
        return False, f"Kaydedilemedi: {e}"

def send_test_mail():
    """Test maili gonderir (mevcut ayarlarla)."""
    import subprocess
    try:
        r = subprocess.run(["/home/yasin/netgate/venv/bin/python3",
                            "/home/yasin/netgate/app/mail_report.py"],
                           capture_output=True, text=True, timeout=60)
        out = (r.stdout + r.stderr).strip()
        if "Mail gonderildi" in out:
            return True, out
        return False, out or "Bilinmeyen sonuc"
    except Exception as e:
        return False, str(e)
