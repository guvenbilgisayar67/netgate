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
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        ip saddr @blocked_ips drop
        ct state established,related accept
        iif "${LAN_IF}" oif "${WAN_IF}" accept
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

echo ""
echo "=== KURULUM TAMAM ==="
echo "Panel: http://${LAN_IP}:8000  (LAN tarafindan)"
echo "Veya WAN IP'sinden: http://<wan-ip>:8000"
echo "Ilk giris: admin / admin"
