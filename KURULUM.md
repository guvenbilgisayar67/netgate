# NetGate - Yeni Makina Kurulum Kilavuzu

Bu kilavuz, bos bir Ubuntu Server makinasina NetGate'i canlidaki ile **ayni ozelliklerle** kurar.
Captive portal kullanicilari **tasinmaz** - her makina kendi kullanici listesine sahiptir (bos baslar).

## Gereksinimler

- Ubuntu Server 24.04 / 26.04 (temiz kurulum)
- **Iki ethernet portu**: biri internete bakan (WAN), biri switch/AP'ye bakan (LAN)
- Kurulum sirasinda internet baglantisi (paketler + kategori listeleri inecek)
- sudo yetkili bir kullanici (Ubuntu kurulumunda olusturdugunuz kullanici)

## Topoloji

```
Internet --(WAN portu)-- [NetGate] --(LAN portu)-- Switch -- Cihazlar
```

LAN tarafi: `10.10.0.1/22` (DHCP araligi 10.10.0.10 - 10.10.3.254). WAN tarafi: DHCP (modem/Clavister'dan IP alir).

## Kurulum Adimlari

Ubuntu'yu kurup kullaniciyla giris yaptiktan sonra, sirayla:

```bash
# 1) Git kur ve projeyi ev dizinine klonla (dizin MUTLAKA ~/netgate olmali)
sudo apt update && sudo apt install -y git
git clone https://github.com/guvenbilgisayar67/netgate ~/netgate

# 2) Kurulumu calistir
cd ~/netgate
chmod +x kur.sh filtre_kur.sh
./kur.sh
```

`./kur.sh` once mevcut ethernet portlarini listeler ve sorar:

```
WAN portu (modeme bakan, internet gelen): <buraya internet gelen portun adini yaz, orn. enp1s0>
LAN portu (AP'ye bakan):                  <buraya switch'e bakan portun adini yaz, orn. enp2s0>
```

> Port adlarini listeden secin. Hangi portun hangisi oldugunu bilmiyorsaniz: internet kablosunun
> takili oldugu port WAN'dir. Emin degilseniz once sadece WAN kablosunu takip `ip -br link` ile
> "UP" olan portu bulabilirsiniz.

Onaydan sonra script her seyi otomatik kurar (yaklasik 3-8 dk, kategori listeleri indigi icin):

- Python ortami + bagimliliklar
- Cekirdek/forward/NAT ayarlari (netplan + nftables + tc)
- DHCP + DNS (dnsmasq) + DNS zorlama + DoH/QUIC/DoT engelleme
- Web panel servisi (netgate.service, port 8000)
- 5651 loglama, oturum suresi timer'i, mail raporu timer'i
- **Grup bazli DNS filtre altyapisi** (filtre_kur.sh otomatik calisir): per-grup dnsmasq profilleri,
  `dns_route` + `dns_route_mac` haritalari (muaf cihazlar MAC'e gore yonlendirilir)

Son satirda `=== KURULUM TAMAM ===` gorursunuz.

## Kurulumdan Sonra

1. Bir tarayicidan panele girin: `http://10.10.0.1:8000` (LAN tarafindan) veya `http://<wan-ip>:8000`
2. **Ilk giris: `admin` / `admin`** - ilk giriste sifre degistirmeniz istenir, degistirin.
3. Hazir gelen filtre gruplari: **personel** (serbest), **ogrenci** (adult+social+games engelli),
   **misafir** (en sinirli). Kategorileri/gruplari panelden duzenleyebilirsiniz.
4. Captive portal **kapali** baslar. Kullanmak isterseniz: Captive Portal menusunden acin ve
   kullanicilarinizi/kodlarinizi ekleyin.
5. Muaf cihazlar (yazici, kamera, bilgisayar sinifi vb.) ile site engelleme listesi **bos** baslar;
   bu makinanin kendi ortamina gore panelden eklenir.

## Guncelleme (ileride kod degisirse)

```bash
cd ~/netgate && git pull
sudo systemctl restart netgate
# nftables/filtre altyapisi degistiyse:
./filtre_kur.sh
```

## Notlar

- **Veritabani (`data/netgate.db`) git'e dahil degildir.** Bu yuzden klonlayinca kullanicilar,
  muaf cihazlar ve engel listesi bos gelir - istenen davranis budur. Her makina bagimsizdir.
- Canlidaki engellenen site listesini/istisna listesini bu makinaya tasimak isterseniz, panelden
  elle ekleyebilir veya ayrica aktarim yapabilirsiniz (varsayilan grup kategorileri zaten temel
  engellemeyi yapar).
- LAN portu adi makinaya gore degisir; script bunu sorar ve `/etc/netgate/lan_if` dosyasina yazar,
  tum bilesenler bu dosyadan okur. Yani farkli makinada farkli port adi sorun olmaz.
