from fastapi import FastAPI, Request, Form, status, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import secrets, pathlib
from app import db, logs, devices, users, settings, categories, portal, reports, netinfo, mailconf
import json

BASE = pathlib.Path(__file__).parent
app = FastAPI(title="NetGate")

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse as _RR

class CaptivePortalMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        host = request.headers.get("host", "")
        # NetGate'in kendi adresleri (panel/hotspot erisimi)
        own = host.startswith("10.10.0.1") or host.startswith("192.168.1.194") or host.startswith("localhost") or host.startswith("127.0.0.1")
        # DNAT ile gelen dis site istegi (host bizim degil) -> hotspot'a yonlendir
        if not own:
            return _RR(url="http://10.10.0.1:8000/hotspot", status_code=302)
        return await call_next(request)

app.add_middleware(CaptivePortalMiddleware)
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32))
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")

db.init_db()
users.init_users()
categories.init_categories()
portal.init_portal()
devices.init_devices()
db.init_whitelist()
try:
    devices.sync_exempt_to_gateway()
except Exception:
    pass
# Filtre profillerini uret + servisleri baslat + aktif oturum yonlendirmelerini geri yukle
try:
    from app import filters as _filters
    _filters.write_group_blocklists()
    _filters.generate_all()
    _filters.apply_all()
except Exception:
    pass
try:
    from app import gateway as _gw, filters as _f
    for _s in portal.list_sessions(active_only=True):
        _port = _f.profile_port(_s["group_name"])
        if _port and _s["ip"]:
            _gw.set_dns_route(_s["ip"], _port)
except Exception:
    pass

def is_logged_in(request: Request) -> bool:
    return request.session.get("user") is not None

# ---------- Giris ----------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})

@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    user = users.verify_user(username, password)
    if user:
        request.session["user"] = user["username"]
        # Sifre degistirmesi gerekiyorsa oraya yonlendir
        if user["must_change"]:
            request.session["must_change"] = True
            return RedirectResponse("/change-password", status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "login.html", {"error": "Kullanici adi veya sifre hatali"})

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

# ---------- Sifre Degistirme ----------

@app.get("/change-password", response_class=HTMLResponse)
def change_pw_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "change_password.html", {
        "user": request.session["user"],
        "forced": request.session.get("must_change", False),
        "msg": None,
    })

@app.post("/change-password")
def change_pw_submit(request: Request, new_password: str = Form(...), new_password2: str = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    if new_password != new_password2:
        return templates.TemplateResponse(request, "change_password.html", {
            "user": request.session["user"], "forced": request.session.get("must_change", False),
            "msg": ("err", "Sifreler eslesmiyor"),
        })
    ok, msg = users.change_password(request.session["user"], new_password)
    if ok:
        request.session.pop("must_change", None)
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "change_password.html", {
        "user": request.session["user"], "forced": request.session.get("must_change", False),
        "msg": ("err", msg),
    })

# ---------- Dashboard ----------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    domains = db.list_domains()
    log_stats = logs.log_stats()
    recent_logs = logs.read_dns_logs(limit=8)
    cats = categories.get_states()
    active_cats = sum(1 for c in cats.values() if c["enabled"])
    total_blocked_sites = sum(c["count"] for c in cats.values() if c["enabled"]) + len(domains)
    sessions = portal.list_sessions(active_only=True)
    try:
        dstats = reports.dashboard_stats()
    except Exception:
        dstats = {"top_sites": [], "top_users": [], "saatlik": [0]*24, "toplam_erisim": 0, "tekil_kullanici": 0, "tekil_cihaz": 0}
    try:
        dextra = reports.dashboard_extra()
    except Exception:
        dextra = {"gunluk_trend": [], "kategori": {}, "engellenen_sayi": 0, "engellenen_top": []}
    return templates.TemplateResponse(request, "dashboard.html", {
        "dstats": dstats,
        "dextra": dextra,
        "user": request.session["user"],
        "blocked_count": len(domains),
        "device_count": devices.device_count(),
        "log_stats": log_stats,
        "recent_logs": recent_logs,
        "active_cats": active_cats,
        "total_blocked_sites": total_blocked_sites,
        "portal_enabled": portal.is_enabled(),
        "active_sessions": len(sessions),
    })

# ---------- Site Engelleme ----------


@app.post("/whitelist/add")
def whitelist_add(request: Request, domain: str = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    db.add_whitelist(domain)
    return RedirectResponse("/blocklist?msg=wl_add", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/whitelist/delete")
def whitelist_delete(request: Request, wid: int = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    db.delete_whitelist(wid)
    return RedirectResponse("/blocklist?msg=wl_del", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/blocklist", response_class=HTMLResponse)
def blocklist_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "blocklist.html", {
        "whitelist": db.list_whitelist(),
        "user": request.session["user"],
        "domains": db.list_domains(),
        "groups": portal.list_groups(),
        "msg": request.query_params.get("msg"),
    })

@app.post("/blocklist/add")
async def blocklist_add(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    form = await request.form()
    domain = form.get("domain", "")
    note = form.get("note", "")
    sel = form.getlist("g")
    groups = "all" if (not sel or "all" in sel) else ",".join(sel)
    if domain.strip():
        ok = db.add_domain(domain, note, groups)
        msg = "eklendi" if ok else "zaten_var"
    else:
        msg = "bos"
    return RedirectResponse(f"/blocklist?msg={msg}", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/blocklist/delete")
def blocklist_delete(request: Request, domain_id: int = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    db.delete_domain(domain_id)
    return RedirectResponse("/blocklist?msg=silindi", status_code=status.HTTP_303_SEE_OTHER)

# ---------- Loglar ----------



@app.get("/netinfo", response_class=HTMLResponse)
def netinfo_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    info = netinfo.get_network_info()
    return templates.TemplateResponse(request, "netinfo.html", {
        "user": request.session["user"], "info": info,
    })

@app.get("/api/traffic")
def api_traffic(request: Request):
    if not is_logged_in(request):
        return JSONResponse({"error": "auth"}, status_code=401)
    return JSONResponse(netinfo.get_traffic_counters())


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    from datetime import date as _date, timedelta as _td
    _today = _date.today().strftime("%Y-%m-%d")
    _week_ago = (_date.today() - _td(days=7)).strftime("%Y-%m-%d")
    q = request.query_params.get("q", "")
    date_from = request.query_params.get("from", "") or _week_ago
    date_to = request.query_params.get("to", "") or _today
    result = {"users": [], "details": []}
    if q or date_from or date_to:
        result = reports.search_user_activity(q, date_from, date_to)
    return templates.TemplateResponse(request, "reports.html", {
        "user": request.session["user"],
        "q": q, "date_from": date_from or "", "date_to": date_to or "",
        "users": result["users"], "details": result["details"],
        "searched": bool(q or date_from or date_to),
    })


@app.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    only_blocked = request.query_params.get("filter") == "blocked"
    search = request.query_params.get("q", "")
    kayitlar = logs.read_dns_logs(limit=200, only_blocked=only_blocked, search=search)
    stats = logs.log_stats()
    return templates.TemplateResponse(request, "logs.html", {
        "user": request.session["user"],
        "logs": kayitlar,
        "stats": stats,
        "only_blocked": only_blocked,
        "search": search,
    })

# ---------- Cihazlar ----------

@app.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    do_scan = request.query_params.get("scan") == "1"
    if do_scan:
        cihazlar = devices.arp_scan()
    else:
        cihazlar = devices.list_devices()
    return templates.TemplateResponse(request, "devices.html", {
        "scanned": do_scan,
        "user": request.session["user"],
        "devices": cihazlar,
        "exempt": devices.list_exempt(),
        "levels": [("_acik","Tam acik"), ("_muaf","Sadece yetiskin engelli")] + [(g["name"], "Grup: "+g["name"]) for g in portal.list_groups()],
        "msg": request.query_params.get("msg"),
    })

@app.post("/devices/name")
def devices_set_name(request: Request, mac: str = Form(...), name: str = Form("")):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    devices.set_device_name(mac, name)
    return RedirectResponse("/devices?msg=name_saved", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/devices/exempt/add")
def devices_exempt_add(request: Request, mac: str = Form(...), ip: str = Form(""), name: str = Form(""), profile: str = Form("_muaf")):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    devices.add_exempt(mac, ip, name, profile)
    return RedirectResponse("/devices?msg=exempt_add#muaf", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/devices/exempt/remove")
def devices_exempt_remove(request: Request, dev_id: int = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    devices.remove_exempt(dev_id)
    return RedirectResponse("/devices?msg=exempt_del#muaf", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/devices/exempt/profile")
def devices_exempt_profile(request: Request, dev_id: int = Form(...), profile: str = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    devices.change_exempt_profile(dev_id, profile)
    return RedirectResponse("/devices?msg=exempt_profile#muaf", status_code=status.HTTP_303_SEE_OTHER)

# ---------- Kullanicilar ----------

@app.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "users.html", {
        "user": request.session["user"],
        "users": users.list_users(),
        "msg": request.query_params.get("msg"),
    })

@app.post("/users/add")
def users_add(request: Request, username: str = Form(...), password: str = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    ok, msg = users.add_user(username, password)
    return RedirectResponse(f"/users?msg={'eklendi' if ok else 'hata'}", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/users/delete")
def users_delete(request: Request, user_id: int = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    ok, msg = users.delete_user(user_id)
    return RedirectResponse(f"/users?msg={'silindi' if ok else 'hata'}", status_code=status.HTTP_303_SEE_OTHER)
# ---------- Ayarlar ----------

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "settings.html", {
        "user": request.session["user"],
        "info": settings.system_info(),
        "msg": request.query_params.get("msg"),
        "mail_conf": mailconf.read_mail_conf(),
        "mail_test_result": request.session.pop("mail_test_result", None),
    })

@app.get("/settings/export")
def settings_export(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    from fastapi.responses import Response
    data = settings.export_config()
    content = json.dumps(data, indent=2, ensure_ascii=False)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=netgate-yedek.json"}
    )


@app.post("/settings/mail")
def settings_mail_save(request: Request, smtp_user: str = Form(""), smtp_password: str = Form(""), mail_to: str = Form(""), period: str = Form("daily")):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    mailconf.save_mail_conf(smtp_user, smtp_password, mail_to, period)
    return RedirectResponse("/settings?msg=mail_saved", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/settings/mail/test")
def settings_mail_test(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    ok, msg = mailconf.send_test_mail()
    m = "mail_test_ok" if ok else "mail_test_fail"
    request.session["mail_test_result"] = msg
    return RedirectResponse(f"/settings?msg={m}", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/settings/import")
async def settings_import(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    form = await request.form()
    upload = form.get("backup_file")
    if upload:
        try:
            content = await upload.read()
            data = json.loads(content)
            count = settings.import_config(data)
            return RedirectResponse(f"/settings?msg=import_{count}", status_code=status.HTTP_303_SEE_OTHER)
        except Exception:
            return RedirectResponse("/settings?msg=import_hata", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/settings?msg=import_hata", status_code=status.HTTP_303_SEE_OTHER)
# ---------- Kategoriler ----------

@app.get("/categories", response_class=HTMLResponse)
def categories_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "categories.html", {
        "user": request.session["user"],
        "categories": categories.get_states(),
        "msg": request.query_params.get("msg"),
    })

@app.post("/categories/toggle")
def categories_toggle(request: Request, key: str = Form(...), action: str = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    if action == "enable":
        ok, msg = categories.enable_category(key)
    else:
        ok, msg = categories.disable_category(key)
    return RedirectResponse("/categories?msg=" + ("ok" if ok else "hata"),
                            status_code=status.HTTP_303_SEE_OTHER)
# ---------- Captive Portal: Yonetim ----------

@app.get("/portal", response_class=HTMLResponse)
def portal_admin(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    bulk_result = request.session.pop("bulk_result", None)
    return templates.TemplateResponse(request, "portal_admin.html", {
        "user": request.session["user"],
        "enabled": portal.is_enabled(),
        "portal_users": portal.list_portal_users(),
        "codes": portal.list_codes(),
        "sessions": portal.list_sessions(active_only=True),
        "groups": portal.list_groups(),
        "msg": request.query_params.get("msg"),
        "bulk_result": bulk_result,
    })

@app.post("/portal/toggle")
def portal_toggle(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.set_enabled(not portal.is_enabled())
    return RedirectResponse("/portal?msg=toggle", status_code=status.HTTP_303_SEE_OTHER)



@app.get("/portal/bulk-template")
def portal_bulk_template(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    from fastapi.responses import Response
    import io
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Kullanicilar"
    ws.append(["ad_soyad", "kullanici_adi", "sifre", "grup"])
    ws.append(["Ali Veli", "", "1111", "ogrenci"])
    ws.append(["Ayse Yilmaz", "ayse.yilmaz", "2222", "ogrenci"])
    ws.append(["Mehmet Demir", "", "3333", "personel"])
    # Sutun genislikleri
    for col, w in zip("ABCD", [22, 18, 12, 12]):
        ws.column_dimensions[col].width = w
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return Response(content=buf.read(),
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": "attachment; filename=kullanici_sablon.xlsx"})

@app.post("/portal/bulk-upload")
async def portal_bulk_upload(request: Request, csv_file: UploadFile = File(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    content = await csv_file.read()
    fname = (csv_file.filename or "").lower()
    if fname.endswith(".xlsx"):
        # Excel dosyasi - openpyxl ile oku, CSV metnine cevir
        import io as _io
        from openpyxl import load_workbook
        wb = load_workbook(_io.BytesIO(content), read_only=True, data_only=True)
        ws = wb.active
        lines = []
        for row in ws.iter_rows(values_only=True):
            cells = ["" if c is None else str(c) for c in row]
            lines.append(";".join(cells))
        text = "\n".join(lines)
    else:
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = content.decode("iso-8859-9", errors="ignore")
    result = portal.bulk_add_users(text)
    request.session["bulk_result"] = result
    return RedirectResponse("/portal?msg=bulk", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/portal/user/change-group")
def portal_user_change_group(request: Request, username: str = Form(...), group_name: str = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.change_user_group(username, group_name)
    return RedirectResponse("/portal?msg=group_changed", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/portal/user/reset-password")
def portal_user_reset_password(request: Request, username: str = Form(...), new_password: str = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.reset_user_password(username, new_password)
    return RedirectResponse("/portal?msg=pw_reset", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/portal/user/add")
def portal_user_add(request: Request, username: str = Form(...), password: str = Form(...),
                    full_name: str = Form(""), group_name: str = Form("ogrenci"),
                    duration_min: int = Form(60), bandwidth_kbps: int = Form(0), max_devices: int = Form(0)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.add_portal_user(username, password, full_name, group_name, duration_min, bandwidth_kbps, max_devices)
    return RedirectResponse("/portal?msg=user_add", status_code=status.HTTP_303_SEE_OTHER)
@app.post("/portal/user/delete")
def portal_user_delete(request: Request, uid: int = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.delete_portal_user(uid)
    return RedirectResponse("/portal?msg=user_del", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/portal/code/add")
def portal_code_add(request: Request, note: str = Form(""), group_name: str = Form("misafir"), duration_min: int = Form(60), count: int = Form(1)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.generate_code(note, group_name, duration_min, count)
    return RedirectResponse("/portal?msg=code_add", status_code=status.HTTP_303_SEE_OTHER)
@app.post("/portal/code/delete")
def portal_code_delete(request: Request, cid: int = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.delete_code(cid)
    return RedirectResponse("/portal?msg=code_del", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/portal/session/end")
def portal_session_end(request: Request, sid: int = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.end_session(sid)
    return RedirectResponse("/portal?msg=sess_end", status_code=status.HTTP_303_SEE_OTHER)

# ---------- Captive Portal: Kullanici Giris Ekrani ----------
# (Gercek makinede, giris yapmamis cihazlar buraya yonlendirilecek)
@app.post("/portal/group/update")
async def portal_group_update(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    form = await request.form()
    name = form.get("name")
    cats = []
    for key in ("ads", "adult", "social", "games"):
        if form.get(f"c_{key}"):
            cats.append(key)
    bw = form.get("bandwidth_kbps", "0")
    try:
        bw = int(bw)
    except ValueError:
        bw = 0
    md = form.get("max_devices", "1")
    try:
        md = int(md)
    except ValueError:
        md = 1
    dur = form.get("duration_min", "60")
    try:
        dur = int(dur)
    except ValueError:
        dur = 60
    fpc = 1 if form.get("force_password_change") else 0
    portal.update_group(name, ",".join(cats), bw, duration_min=dur, max_devices=md, force_password_change=fpc)
    # Kategoriler degisti -> bu grubun DNS filtre profilini yeniden uret + baslat
    try:
        from app import filters as _filters
        _filters.generate_all()
        _filters.restart_profile(name)
    except Exception:
        pass
    return RedirectResponse("/portal?msg=group_upd", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/portal/group/create")
def portal_group_create(request: Request, name: str = Form(...), bandwidth_kbps: int = Form(0), duration_min: int = Form(60)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.create_group(name, bandwidth_kbps, duration_min)
    return RedirectResponse("/portal?msg=group_create", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/portal/group/delete")
def portal_group_delete(request: Request, name: str = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.delete_group(name)
    return RedirectResponse("/portal?msg=group_delete", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/hotspot", response_class=HTMLResponse)
def hotspot_page(request: Request):
    return templates.TemplateResponse(request, "hotspot.html", {"error": None})

@app.post("/hotspot")
def hotspot_login(request: Request, identity: str = Form(""), secret: str = Form(...)):
    client_ip = request.client.host if request.client else ""
    try:
        from app import gateway
        real_mac = gateway.mac_from_ip(client_ip)
    except Exception:
        real_mac = ""
    result, msg = portal.portal_login(identity, secret, ip=client_ip, mac=real_mac)
    if result == "LIMIT":
        parts = msg.split("||")
        ident = parts[0]
        limit = parts[1] if len(parts) > 1 else "1"
        devices_raw = parts[2] if len(parts) > 2 else ""
        dev_list = []
        for d in devices_raw.split("|"):
            if not d:
                continue
            f = d.split(",")
            if len(f) >= 4:
                dev_list.append({"id": f[0], "mac": f[1], "ip": f[2], "started": f[3], "name": f[4] if len(f) > 4 else ""})
        return templates.TemplateResponse(request, "hotspot.html", {
            "error": None, "limit_reached": True, "identity": ident,
            "limit": limit, "active_devices": dev_list})
    if result == "CHANGE_PW":
        return templates.TemplateResponse(request, "hotspot.html", {
            "error": None, "change_pw": True, "identity": msg})
    if result is True:
        return templates.TemplateResponse(request, "hotspot.html", {"error": None, "success": msg})
    return templates.TemplateResponse(request, "hotspot.html", {"error": msg})

@app.post("/hotspot/change-password")
def hotspot_change_password(request: Request, identity: str = Form(...), old_secret: str = Form(...), new_password: str = Form(...), new_password2: str = Form(...)):
    # Once eski sifreyle dogrula (guvenlik)
    client_ip = request.client.host if request.client else ""
    try:
        from app import gateway
        real_mac = gateway.mac_from_ip(client_ip)
    except Exception:
        real_mac = ""
    # Eski sifre dogru mu (portal_login CHANGE_PW donerse dogru demek)
    check, _ = portal.portal_login(identity, old_secret, ip=client_ip, mac=real_mac)
    if check != "CHANGE_PW" and check is not True:
        return templates.TemplateResponse(request, "hotspot.html", {
            "error": "Mevcut sifre hatali", "change_pw": True, "identity": identity})
    if new_password != new_password2:
        return templates.TemplateResponse(request, "hotspot.html", {
            "error": "Yeni sifreler eslesmiyor", "change_pw": True, "identity": identity})
    ok, pmsg = portal.change_own_password(identity, new_password)
    if not ok:
        return templates.TemplateResponse(request, "hotspot.html", {
            "error": pmsg, "change_pw": True, "identity": identity})
    # Sifre degisti - simdi yeni sifreyle otomatik giris yap (internete ac)
    result, lmsg = portal.portal_login(identity, new_password, ip=client_ip, mac=real_mac)
    if result is True:
        return templates.TemplateResponse(request, "hotspot.html", {"error": None, "success": lmsg})
    return templates.TemplateResponse(request, "hotspot.html", {"error": None, "success": "Sifreniz belirlendi. Tekrar giris yapabilirsiniz."})

@app.post("/hotspot/close-session")
def hotspot_close_session(request: Request, identity: str = Form(...), secret: str = Form(...), session_id: int = Form(...)):
    ok, msg = portal.close_session_with_password(session_id, identity, secret)
    if ok:
        client_ip = request.client.host if request.client else ""
        try:
            from app import gateway
            real_mac = gateway.mac_from_ip(client_ip)
        except Exception:
            real_mac = ""
        result, lmsg = portal.portal_login(identity, secret, ip=client_ip, mac=real_mac)
        if result is True:
            return templates.TemplateResponse(request, "hotspot.html", {"error": None, "success": lmsg})
    return templates.TemplateResponse(request, "hotspot.html", {"error": msg or "Islem basarisiz"})