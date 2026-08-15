from fastapi import FastAPI, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import secrets, pathlib
from app import db, logs, devices, users, settings, categories, portal
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
    return templates.TemplateResponse(request, "dashboard.html", {
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
        "msg": request.query_params.get("msg"),
    })

@app.post("/blocklist/add")
def blocklist_add(request: Request, domain: str = Form(...), note: str = Form("")):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    if domain.strip():
        ok = db.add_domain(domain, note)
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
    cihazlar = devices.list_devices()
    return templates.TemplateResponse(request, "devices.html", {
        "user": request.session["user"],
        "devices": cihazlar,
        "exempt": devices.list_exempt(),
        "msg": request.query_params.get("msg"),
    })

@app.post("/devices/exempt/add")
def devices_exempt_add(request: Request, mac: str = Form(...), ip: str = Form(""), name: str = Form("")):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    devices.add_exempt(mac, ip, name)
    return RedirectResponse("/devices?msg=exempt_add", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/devices/exempt/remove")
def devices_exempt_remove(request: Request, dev_id: int = Form(...)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    devices.remove_exempt(dev_id)
    return RedirectResponse("/devices?msg=exempt_del", status_code=status.HTTP_303_SEE_OTHER)

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
    return templates.TemplateResponse(request, "portal_admin.html", {
        "user": request.session["user"],
        "enabled": portal.is_enabled(),
        "portal_users": portal.list_portal_users(),
        "codes": portal.list_codes(),
        "sessions": portal.list_sessions(active_only=True),
        "groups": portal.list_groups(),
        "msg": request.query_params.get("msg"),
    })

@app.post("/portal/toggle")
def portal_toggle(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.set_enabled(not portal.is_enabled())
    return RedirectResponse("/portal?msg=toggle", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/portal/user/add")
def portal_user_add(request: Request, username: str = Form(...), password: str = Form(...),
                    full_name: str = Form(""), group_name: str = Form("ogrenci"),
                    duration_min: int = Form(60), bandwidth_kbps: int = Form(0)):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    portal.add_portal_user(username, password, full_name, group_name, duration_min, bandwidth_kbps)
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
    portal.update_group(name, ",".join(cats), bw)
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
    ok, msg = portal.portal_login(identity, secret, ip=client_ip, mac="")
    if ok:
        return templates.TemplateResponse(request, "hotspot.html", {"error": None, "success": msg})
    return templates.TemplateResponse(request, "hotspot.html", {"error": msg})