from fastapi import FastAPI, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import secrets, pathlib
from app import db, logs, devices, users, settings, categories
import json

BASE = pathlib.Path(__file__).parent
app = FastAPI(title="NetGate")
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32))
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")

db.init_db()
users.init_users()
categories.init_categories()

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
    return templates.TemplateResponse(request, "dashboard.html", {
        "user": request.session["user"],
        "blocked_count": len(domains),
        "device_count": devices.device_count(),
    })

# ---------- Site Engelleme ----------

@app.get("/blocklist", response_class=HTMLResponse)
def blocklist_page(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "blocklist.html", {
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
    })

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