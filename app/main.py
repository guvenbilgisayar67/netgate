from fastapi import FastAPI, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import secrets, pathlib
from app import db

BASE = pathlib.Path(__file__).parent
app = FastAPI(title="NetGate")
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32))
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")

ADMIN_USER = "admin"
ADMIN_PASS = "admin"

db.init_db()

def is_logged_in(request: Request) -> bool:
    return request.session.get("user") is not None

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})

@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        request.session["user"] = username
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "login.html", {"error": "Kullanici adi veya sifre hatali"})

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    domains = db.list_domains()
    return templates.TemplateResponse(request, "dashboard.html", {
        "user": request.session["user"],
        "blocked_count": len(domains),
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