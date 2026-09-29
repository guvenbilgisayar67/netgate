"""NetGate - Grup bazli DNS filtre profilleri.

Mimari:
- Her kategori icin domain listesi bir kez cache'lenir: /etc/netgate/catcache/<key>.conf
- Her grup (+ ozel "_acik"/"_muaf" profilleri) icin bir dnsmasq instance calisir, kendi portunda,
  SADECE o profilin kategorilerini + gruba ozel elle-engel listesini engeller. DNS-only.
- Kullanici giriste IP'si grubunun nft setine eklenir; nftables o IP'nin DNS'ini
  ilgili profil portuna yonlendirir (gateway.py).

Servisler: netgate-dns@<profil>.service (systemd template unit).
"""
import subprocess
import pathlib
from app.db import get_conn
from app import categories as cats_mod

CATCACHE_DIR = "/etc/netgate/catcache"
PROFILE_DIR = "/etc/netgate/profiles"
BLOCKLIST_CONF = "/etc/netgate/blocklist.conf"
GBLOCK_DIR = "/etc/netgate/gblock"   # grup bazli elle-engel dosyalari
LAN_IP = "10.10.0.1"

ACIK_NAME = "_acik"        # tam acik profil (hicbir sey engellenmez)
MUAF_NAME = "_muaf"
MUAF_CATS = ["adult"]      # muaf cihazlarin engelli kategorileri (yasal minimum)
BASE_PORT = 5300           # profil portlari: BASE+1...; _acik=BASE+98, _muaf=BASE+99

# ---------- Kategori cache ----------

def build_catcache():
    """Tum kategorilerin domain listesini catcache/<key>.conf olarak yazar."""
    pathlib.Path(CATCACHE_DIR).mkdir(parents=True, exist_ok=True)
    import urllib.request
    written = {}
    for key, cat in cats_mod.CATEGORIES.items():
        if cat["type"] == "url":
            try:
                req = urllib.request.Request(cat["url"], headers={"User-Agent": "NetGate"})
                text = urllib.request.urlopen(req, timeout=45).read().decode("utf-8", "ignore")
                domains = cats_mod._parse_hosts(text)
            except Exception:
                written[key] = _count_cache(key)
                continue
        else:
            domains = set(cat["domains"])
        path = f"{CATCACHE_DIR}/{key}.conf"
        with open(path, "w") as f:
            for dom in sorted(domains):
                f.write(f"address=/{dom}/0.0.0.0\n")
                f.write(f"address=/{dom}/::\n")
        written[key] = len(domains)
    return written

def _count_cache(key):
    try:
        with open(f"{CATCACHE_DIR}/{key}.conf") as f:
            return sum(1 for ln in f if ln.rstrip().endswith("/0.0.0.0"))
    except Exception:
        return 0

# ---------- Profil tanimlari ----------

def _profiles():
    """[(ad, [kategoriler], port)] - _acik + _muaf + her grup."""
    conn = get_conn()
    groups = conn.execute("SELECT name, categories FROM portal_groups ORDER BY name").fetchall()
    conn.close()
    profs = [(ACIK_NAME, [], BASE_PORT + 98), (MUAF_NAME, list(MUAF_CATS), BASE_PORT + 99)]
    for i, g in enumerate(groups):
        cats = [c.strip() for c in (g["categories"] or "").split(",") if c.strip()]
        profs.append((g["name"], cats, BASE_PORT + 1 + i))
    return profs

def profile_port(name):
    for n, cats, port in _profiles():
        if n == name:
            return port
    return None

def list_profiles():
    return [{"name": n, "cats": c, "port": p} for n, c, p in _profiles()]

# ---------- Grup bazli elle-engel dosyalari ----------

def write_group_blocklists():
    """Her grup icin elle-engellenen siteleri gblock/<grup>.conf'a yazar.
    'all' gruplu domain tum gruplara, digerleri sadece secili gruplara uygulanir."""
    from app.db import list_domains, list_whitelist
    pathlib.Path(GBLOCK_DIR).mkdir(parents=True, exist_ok=True)
    try:
        exempt = {w["domain"] for w in list_whitelist()}
    except Exception:
        exempt = set()
    domains = list_domains()
    conn = get_conn()
    groups = [g["name"] for g in conn.execute("SELECT name FROM portal_groups").fetchall()]
    conn.close()
    for gname in groups:
        lines = []
        for d in domains:
            dom = d["domain"]
            if dom in exempt:
                continue
            grp = d["groups"] if ("groups" in d.keys() and d["groups"]) else "all"
            applies = (grp == "all") or (gname in [x.strip() for x in grp.split(",")])
            if applies:
                lines.append(f"address=/{dom}/0.0.0.0")
                lines.append(f"address=/{dom}/::")
        with open(f"{GBLOCK_DIR}/{gname}.conf", "w") as f:
            f.write("\n".join(lines) + "\n")

# ---------- dnsmasq instance config uretimi ----------

def _write_profile_conf(name, cats, port):
    pdir = f"{PROFILE_DIR}/{name}"
    pathlib.Path(pdir).mkdir(parents=True, exist_ok=True)
    lines = [
        f"# NetGate filtre profili: {name} (kategoriler: {','.join(cats) or 'YOK'})",
        f"port={port}",
        "bind-interfaces",
        f"listen-address={LAN_IP}",
        "listen-address=127.0.0.1",
        "cache-size=1000",
        "server=8.8.8.8",
        "server=8.8.4.4",
    ]
    for key in cats:
        cache = f"{CATCACHE_DIR}/{key}.conf"
        if pathlib.Path(cache).exists():
            lines.append(f"conf-file={cache}")
    # Gruba ozel elle-engel listesi (muaf/acik haric)
    if name not in (MUAF_NAME, ACIK_NAME):
        gblock = f"{GBLOCK_DIR}/{name}.conf"
        if pathlib.Path(gblock).exists():
            lines.append(f"conf-file={gblock}")
    conf_path = f"{pdir}/dnsmasq.conf"
    with open(conf_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return conf_path

def generate_all():
    return [{"name": n, "cats": c, "port": p, "conf": _write_profile_conf(n, c, p)}
            for n, c, p in _profiles()]

# ---------- Servis yonetimi (systemd template: netgate-dns@<ad>) ----------

def _sudo(*args):
    try:
        r = subprocess.run(["sudo"] + list(args), capture_output=True, text=True, timeout=30)
        return r.returncode == 0, (r.stdout + r.stderr)
    except Exception as e:
        return False, str(e)

def restart_profile(name):
    return _sudo("/usr/local/sbin/netgate-dns-ctl", "restart", name)

def apply_all():
    """Config'leri uret + tum profil servislerini yeniden baslat."""
    gen = generate_all()
    results = []
    for g in gen:
        ok, out = restart_profile(g["name"])
        results.append({"name": g["name"], "port": g["port"], "restarted": ok})
    return results

def rebuild_manual_blocks():
    """Elle-engel degisince: grup dosyalarini yaz + profilleri yeniden uret/baslat."""
    write_group_blocklists()
    generate_all()
    for name, cats, port in _profiles():
        if name not in (MUAF_NAME, ACIK_NAME):
            restart_profile(name)

if __name__ == "__main__":
    for p in list_profiles():
        print(p)
