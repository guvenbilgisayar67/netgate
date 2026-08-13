#!/bin/bash
# ============================================================
# NetGate - Gercek Makine Kurulum Scripti
# Ubuntu Server 24.04/26.04 icin
# Calistirma: bash kur.sh
# ============================================================
set -e

PROJE_DIZIN="$HOME/netgate"
KULLANICI="$USER"

echo "=========================================="
echo " NetGate Kurulumu Basliyor"
echo " Kullanici: $KULLANICI"
echo " Dizin: $PROJE_DIZIN"
echo "=========================================="

echo ""
echo "[1/7] Sistem paketleri kuruluyor..."
sudo apt update
sudo apt install -y python3-pip python3-venv git nftables dnsmasq sqlite3 curl ethtool

echo ""
echo "[2/7] Python sanal ortami olusturuluyor..."
cd "$PROJE_DIZIN"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install fastapi "uvicorn[standard]" jinja2 python-multipart itsdangerous bcrypt

echo ""
echo "[3/7] dnsmasq ve systemd-resolved ayarlaniyor..."
# systemd-resolved 53 portunu biraksin
sudo mkdir -p /etc/systemd/resolved.conf.d
echo -e "[Resolve]\nDNSStubListener=no" | sudo tee /etc/systemd/resolved.conf.d/netgate.conf
sudo systemctl restart systemd-resolved
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

echo ""
echo "[4/7] NetGate dizinleri ve engel dosyalari olusturuluyor..."
sudo mkdir -p /etc/netgate/categories
sudo touch /etc/netgate/blocklist.conf
sudo chown -R "$KULLANICI" /etc/netgate

echo ""
echo "[5/7] dnsmasq yapilandirmasi yaziliyor..."
sudo tee /etc/dnsmasq.d/netgate.conf > /dev/null << DNSEOF
# Ust DNS sunuculari
server=1.1.1.1
server=8.8.8.8
cache-size=10000
# Localhost dinle (test icin; gercek agda interface ayari eklenecek)
listen-address=127.0.0.1
bind-interfaces
# Loglama (5651)
log-queries=extra
log-facility=/var/log/netgate-dns.log
# Engel listeleri
conf-file=/etc/netgate/blocklist.conf
conf-dir=/etc/netgate/categories/,*.conf
DNSEOF
sudo touch /var/log/netgate-dns.log
sudo chmod 644 /var/log/netgate-dns.log
sudo systemctl restart dnsmasq

echo ""
echo "[6/7] Sudo izinleri (panelin dnsmasq'i yenilemesi + log okumasi)..."
echo "$KULLANICI ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload dnsmasq, /usr/bin/systemctl restart dnsmasq, /usr/bin/tail" | sudo tee /etc/sudoers.d/netgate

echo ""
echo "[7/7] systemd servisi kuruluyor..."
sudo tee /etc/systemd/system/netgate.service > /dev/null << SVCEOF
[Unit]
Description=NetGate Web Panel
After=network.target

[Service]
Type=simple
User=$KULLANICI
WorkingDirectory=$PROJE_DIZIN
ExecStart=$PROJE_DIZIN/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF
sudo systemctl daemon-reload
sudo systemctl enable netgate
sudo systemctl start netgate

echo ""
echo "=========================================="
echo " KURULUM TAMAM!"
echo " Panel: http://<makine-ip>:8000"
echo " Ilk giris: admin / admin (ilk giriste degistirilecek)"
echo " Servis durumu: sudo systemctl status netgate"
echo "=========================================="