#!/bin/bash
# NetGate - Grup bazli DNS filtre sistemi kurulumu (idempotent, tekrar calistirilabilir)
# Canlida git pull sonrasi bu script filtre altyapisini kurar.
set -e
PROJE="${PROJE_DIZIN:-$HOME/netgate}"
KULLANICI="${KULLANICI:-$(whoami)}"
LAN_IF="$(cat /etc/netgate/lan_if 2>/dev/null || echo enp42s0)"
PY="$PROJE/venv/bin/python3"; [ -x "$PY" ] || PY="python3"
echo "=== NetGate filtre kurulumu (LAN=$LAN_IF, kullanici=$KULLANICI) ==="

echo "[1/6] systemd template netgate-dns@..."
sudo tee /etc/systemd/system/netgate-dns@.service >/dev/null <<EOF
[Unit]
Description=NetGate DNS filtre profili %i
After=network-online.target
[Service]
ExecStart=/usr/sbin/dnsmasq -C /etc/netgate/profiles/%i/dnsmasq.conf -k
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload

echo "[2/6] wrapper + sudoers (app profilleri yonetebilsin)..."
sudo tee /usr/local/sbin/netgate-dns-ctl >/dev/null <<'EOF'
#!/bin/bash
action="$1"; name="$2"
case "$action" in restart|start|stop|reload) ;; *) echo "gecersiz islem"; exit 1;; esac
case "$name" in *[!A-Za-z0-9_]*|"") echo "gecersiz profil"; exit 1;; esac
exec systemctl "$action" "netgate-dns@$name"
EOF
sudo chmod 755 /usr/local/sbin/netgate-dns-ctl
echo "$KULLANICI ALL=(ALL) NOPASSWD: /usr/local/sbin/netgate-dns-ctl" | sudo tee /etc/sudoers.d/netgate-dns >/dev/null
sudo visudo -c -f /etc/sudoers.d/netgate-dns

echo "[3/6] nftables dns_route map + yonlendirme kurallari..."
if sudo grep -q "map dns_route" /etc/nftables.conf; then
  echo "  zaten mevcut, atlandi"
else
  sudo cp /etc/nftables.conf "/etc/nftables.conf.bak-$(date +%s)"
  sudo "$PY" - "$LAN_IF" <<'PYEOF'
import sys, re
lan = sys.argv[1]; p = "/etc/nftables.conf"; s = open(p).read()
# 1) map ekle (blocked_ips set'inden sonra)
s2 = re.sub(r'(set blocked_ips \{[^}]*\})',
            r'\1\n\n\tmap dns_route {\n\t\ttype ipv4_addr : ipv4_addr . inet_service\n\t}', s, count=1)
assert s2 != s, "blocked_ips set bulunamadi"
s = s2
# 2) prerouting: yonlendirmeyi fallback DNS DNAT'tan ONCE ekle
pat = r'(\n[ \t]*iif "' + re.escape(lan) + r'" udp dport 53 ip daddr != [0-9.]+ dnat ip to [0-9.]+:53)'
ins = (r'\n\t\tiif "' + lan + r'" udp dport 53 dnat ip to ip saddr map @dns_route'
       r'\n\t\tiif "' + lan + r'" tcp dport 53 dnat ip to ip saddr map @dns_route\1')
s2 = re.sub(pat, ins, s, count=1)
assert s2 != s, "fallback DNS kurali bulunamadi"
open(p, "w").write(s2)
print("  nftables.conf guncellendi")
PYEOF
  sudo nft -f /etc/nftables.conf
  echo "  nftables yeniden yuklendi"
fi

echo "[4/6] kategori cache (buyuk listeler inecek, biraz surebilir)..."
cd "$PROJE" && "$PY" -c "from app import filters; print('  ', filters.build_catcache())"

echo "[5/6] profil config'leri + servisleri baslat..."
cd "$PROJE" && "$PY" -c "from app import filters; filters.write_group_blocklists(); [print('   profil:', g['name'], 'port', g['port']) for g in filters.generate_all()]"
PROFILLER="$(cd "$PROJE" && "$PY" -c "from app import filters; print(' '.join(p['name'] for p in filters.list_profiles()))")"
for prof in $PROFILLER; do sudo systemctl enable --now "netgate-dns@$prof" >/dev/null 2>&1 || true; done

echo "[6/6] durum:"
for prof in $PROFILLER; do echo -n "   $prof: "; systemctl is-active "netgate-dns@$prof"; done
echo "=== Filtre kurulumu tamamlandi ==="
