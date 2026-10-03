#!/bin/bash
# NetGate - MODEM/TEST MODU Kurulum
# WAN: DHCP (modemden IP alir) | LAN: 10.10.0.0/22
set -e
PROJE_DIZIN="$HOME/netgate"
KULLANICI="$USER"

echo "=== NetGate TEST Kurulumu ==="
echo "Mevcut arayuzler:"
ip -br link show | grep -v "lo "
echo ""
read -p "WAN portu (modeme bakan, internet gelen): " WAN_IF
read -p "LAN portu (AP'ye bakan): " LAN_IF

LAN_IP="10.10.0.1"
LAN_CIDR="10.10.0.1/22"
DHCP_START="10.10.0.10"
DHCP_END="10.10.3.254"
DHCP_LEASE="4h"

echo ""
echo "WAN: $WAN_IF (DHCP - modemden)"
echo "LAN: $LAN_IF -> $LAN_IP/22"
read -p "Devam? (e/h): " ONAY
[ "$ONAY" != "e" ] && echo "Iptal." && exit 1

echo "[1/9] Paketler..."
sudo apt update
sudo apt install -y python3-pip python3-venv git nftables dnsmasq sqlite3 curl ethtool iproute2

echo "[2/9] Python ortami..."
cd "$PROJE_DIZIN"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install fastapi "uvicorn[standard]" jinja2 python-multipart itsdangerous bcrypt

echo "[3/9] Cekirdek ayarlari..."
sudo tee /etc/sysctl.d/99-netgate.conf > /dev/null << EOF
net.ipv4.ip_forward=1
net.netfilter.nf_conntrack_max=1048576
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.netdev_max_backlog=5000
EOF
sudo sysctl -p /etc/sysctl.d/99-netgate.conf || true

echo "[4/9] Ag arayuzleri (WAN=DHCP, LAN=statik)..."
sudo rm -f /etc/netplan/50-gecici.yaml
sudo tee /etc/netplan/60-netgate.yaml > /dev/null << EOF
network:
  version: 2
  ethernets:
    ${WAN_IF}:
      dhcp4: true
    ${LAN_IF}:
      dhcp4: false
      addresses: [${LAN_CIDR}]
EOF
sudo chmod 600 /etc/netplan/60-netgate.yaml
sudo netplan apply

echo "[5/9] NAT + firewall + tc..."
sudo tee /etc/nftables.conf > /dev/null << EOF
#!/usr/sbin/nft -f
flush ruleset
table inet netgate {
    set allowed_macs { type ether_addr; }
    set blocked_ips { type ipv4_addr; flags interval; }
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif "lo" accept
        iif "${LAN_IF}" accept
        iif "${WAN_IF}" icmp type echo-request accept
        iif "${WAN_IF}" tcp dport 8000 accept
        iif "${WAN_IF}" tcp dport 22 accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        ip saddr @blocked_ips drop
        ct state established,related accept
        iif "${LAN_IF}" ip daddr ${LAN_IP} accept
        iif "${LAN_IF}" udp dport 53 accept
        iif "${LAN_IF}" tcp dport 53 accept
        iif "${LAN_IF}" ether saddr @allowed_macs oif "${WAN_IF}" accept
    }
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iif "${LAN_IF}" ether saddr != @allowed_macs tcp dport 80 dnat ip to ${LAN_IP}:8000
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oif "${WAN_IF}" masquerade
    }
}
EOF
sudo systemctl enable nftables
sudo systemctl restart nftables
sudo tc qdisc del dev ${LAN_IF} root 2>/dev/null || true
sudo tc qdisc add dev ${LAN_IF} root handle 1: htb default 999 2>/dev/null || true
sudo tc class add dev ${LAN_IF} parent 1: classid 1:999 htb rate 1000mbit 2>/dev/null || true

echo "[6/9] DHCP + DNS (dnsmasq)..."
sudo mkdir -p /etc/systemd/resolved.conf.d
echo -e "[Resolve]\nDNSStubListener=no" | sudo tee /etc/systemd/resolved.conf.d/netgate.conf
sudo systemctl restart systemd-resolved
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo mkdir -p /etc/netgate/categories /etc/netgate/group_filters
sudo touch /etc/netgate/blocklist.conf
echo "${LAN_IF}" | sudo tee /etc/netgate/lan_if > /dev/null
sudo chown -R "$KULLANICI" /etc/netgate
sudo tee /etc/dnsmasq.conf > /dev/null << EOF
interface=${LAN_IF}
bind-interfaces
dhcp-range=${DHCP_START},${DHCP_END},255.255.252.0,${DHCP_LEASE}
dhcp-option=option:router,${LAN_IP}
dhcp-option=option:dns-server,${LAN_IP}
dhcp-authoritative
dhcp-lease-max=1200
server=1.1.1.1
server=8.8.8.8
cache-size=10000
log-queries=extra
log-dhcp
log-facility=/var/log/netgate-dns.log
conf-file=/etc/netgate/blocklist.conf
conf-dir=/etc/netgate/categories/,*.conf
EOF
sudo touch /var/log/netgate-dns.log
sudo chmod 644 /var/log/netgate-dns.log
sudo systemctl enable dnsmasq
sudo systemctl restart dnsmasq

echo "[7/9] Log rotasyonu..."
sudo tee /etc/logrotate.d/netgate > /dev/null << EOF
/var/log/netgate-dns.log {
    daily
    rotate 730
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl kill -s HUP dnsmasq 2>/dev/null || true
    endscript
}
EOF

echo "[8/9] Sudo izinleri..."
echo "$KULLANICI ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload dnsmasq, /usr/bin/systemctl restart dnsmasq, /usr/bin/tail, /usr/sbin/nft, /usr/sbin/tc" | sudo tee /etc/sudoers.d/netgate

echo "[9/9] systemd servisi..."
sudo tee /etc/systemd/system/netgate.service > /dev/null << EOF
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
EOF
sudo systemctl daemon-reload
sudo systemctl enable netgate
sudo systemctl start netgate


echo "[10/19] Ek paketler (arp-scan, openpyxl)..."
sudo apt install -y arp-scan
"$PROJE_DIZIN/venv/bin/pip" install openpyxl

echo "[11/19] arp-scan sudo izni..."
echo "$KULLANICI ALL=(ALL) NOPASSWD: /usr/sbin/arp-scan" | sudo tee /etc/sudoers.d/netgate-arpscan

echo "[12/19] WAN portu kaydet..."
echo "${WAN_IF}" | sudo tee /etc/netgate/wan_if > /dev/null

echo "[13/19] nftables DNS zorlama + DoH/QUIC engelleme..."
sudo tee /etc/nftables.conf > /dev/null << NFTEOF
#!/usr/sbin/nft -f
flush ruleset
table inet netgate {
    set allowed_macs { type ether_addr; }
    set blocked_ips { type ipv4_addr; flags interval; }
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif "lo" accept
        iif "${LAN_IF}" accept
        iif "${WAN_IF}" icmp type echo-request accept
        iif "${WAN_IF}" tcp dport 8000 accept
        iif "${WAN_IF}" tcp dport 22 accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        ip saddr @blocked_ips drop
        ct state established,related accept
        iif "${LAN_IF}" ip daddr ${LAN_IP} accept
        iif "${LAN_IF}" udp dport 53 accept
        iif "${LAN_IF}" tcp dport 53 accept
        iif "${LAN_IF}" ip daddr { 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9, 149.112.112.112 } tcp dport 443 drop
        iif "${LAN_IF}" udp dport 443 drop
        iif "${LAN_IF}" ether saddr @allowed_macs oif "${WAN_IF}" accept
    }
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iif "${LAN_IF}" ether saddr != @allowed_macs tcp dport 80 dnat ip to ${LAN_IP}:8000
        iif "${LAN_IF}" udp dport 53 ip daddr != ${LAN_IP} dnat ip to ${LAN_IP}:53
        iif "${LAN_IF}" tcp dport 53 ip daddr != ${LAN_IP} dnat ip to ${LAN_IP}:53
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oif "${WAN_IF}" masquerade
    }
}
NFTEOF
sudo systemctl restart nftables

echo "[14/19] whitelist.conf + dnsmasq ayari..."
sudo touch /etc/netgate/whitelist.conf
sudo chown "$KULLANICI" /etc/netgate/whitelist.conf
grep -q "whitelist.conf" /etc/dnsmasq.conf || echo "conf-file=/etc/netgate/whitelist.conf" | sudo tee -a /etc/dnsmasq.conf
sudo systemctl restart dnsmasq

echo "[15/19] DNS logrotate copytruncate..."
sudo tee /etc/logrotate.d/netgate > /dev/null << LREOF
/var/log/netgate-dns.log {
    su root root
    daily
    rotate 730
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LREOF

echo "[16/19] 5651 gunluk log klasoru + servis..."
sudo mkdir -p /var/log/netgate5651
sudo chmod 755 /var/log/netgate5651
sudo tee /etc/systemd/system/netgate-5651.service > /dev/null << SVEOF
[Unit]
Description=NetGate 5651 Log Servisi
After=netgate.service dnsmasq.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 $PROJE_DIZIN/app/logger5651.py
Restart=always
RestartSec=5
User=root
[Install]
WantedBy=multi-user.target
SVEOF
sudo systemctl daemon-reload
sudo systemctl enable netgate-5651
sudo systemctl start netgate-5651

echo "[17/19] 5651 logrotate..."
sudo tee /etc/logrotate.d/netgate5651-daily > /dev/null << LR2EOF
/var/log/netgate5651/*.log {
    su root root
    daily
    rotate 730
    missingok
    notifempty
    nocompress
    maxage 730
}
LR2EOF

echo "[18/19] Oturum suresi timer..."
sudo tee /etc/systemd/system/netgate-expire.service > /dev/null << EXEOF
[Unit]
Description=NetGate Oturum Suresi Kontrolu
After=netgate.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $PROJE_DIZIN/app/expire_runner.py
User=root
EXEOF
sudo tee /etc/systemd/system/netgate-expire.timer > /dev/null << EXTEOF
[Unit]
Description=NetGate oturum suresi kontrolu (her 5 dakika)
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EXTEOF
sudo systemctl daemon-reload
sudo systemctl enable netgate-expire.timer
sudo systemctl start netgate-expire.timer

echo "[19/19] Mail raporu (config sablonu + timer)..."
if [ ! -f /etc/netgate/mail.conf ]; then
sudo tee /etc/netgate/mail.conf > /dev/null << MAILEOF
# NetGate mail ayarlari - panelden doldurun (Ayarlar > Mail Raporu)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=GONDEREN_GMAIL_ADRESI
SMTP_PASSWORD=UYGULAMA_SIFRESI_16_HANE
MAIL_TO=ALICI_ADRES
PERIOD=daily
MAILEOF
fi
sudo chmod 600 /etc/netgate/mail.conf
sudo chown "$KULLANICI" /etc/netgate/mail.conf
sudo tee /etc/systemd/system/netgate-mail.service > /dev/null << MSEOF
[Unit]
Description=NetGate Gunluk Log Mail Raporu
After=network-online.target
[Service]
Type=oneshot
ExecStart=$PROJE_DIZIN/venv/bin/python3 $PROJE_DIZIN/app/mail_report.py
User=$KULLANICI
MSEOF
sudo tee /etc/systemd/system/netgate-mail.timer > /dev/null << MTEOF
[Unit]
Description=NetGate mail raporu (her aksam 23:00)
[Timer]
OnCalendar=*-*-* 23:00:00
Persistent=true
[Install]
WantedBy=timers.target
MTEOF
sudo systemctl daemon-reload
sudo systemctl enable netgate-mail.timer
sudo systemctl start netgate-mail.timer

echo "[SON-1] Veritabani ilk kurulum (admin + varsayilan gruplar, portal kullanicilari BOS)..."
# Servis zaten DB'yi olusturur ama garanti icin acikca init et (gruplar filtre_kur.sh'ten once hazir olsun)
"$PROJE_DIZIN/venv/bin/python3" -c "from app import db,users,categories,portal,devices; db.init_db(); users.init_users(); categories.init_categories(); portal.init_portal(); devices.init_devices(); db.init_whitelist(); print('  DB hazir')" || true

echo "[SON-2] Grup bazli DNS filtre altyapisi (filtre_kur.sh)..."
# dns_route + dns_route_mac haritalari, per-grup dnsmasq profilleri, DoT/DoH engelleme, kategori cache
PROJE_DIZIN="$PROJE_DIZIN" KULLANICI="$KULLANICI" bash "$PROJE_DIZIN/filtre_kur.sh"

echo ""
echo "=== KURULUM TAMAM ==="
echo "Panel: http://${LAN_IP}:8000  (LAN tarafindan)"
echo "Veya WAN IP'sinden: http://<wan-ip>:8000"
echo "Ilk giris: admin / admin  (ilk giriste sifre degistirmeniz istenir)"
echo "Captive portal kullanicilari BOS baslar - panelden ekleyebilirsiniz (Captive Portal menusu)."
