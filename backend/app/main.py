from pathlib import Path
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from .api import api
from .config import settings
from .db import SessionLocal, engine
from .engine import record_host_metrics, watchdog_tick, _expire_access
from .provision import refresh_client_configs, restore_enabled_peers
from .models import Base
from .nft import apply_acl
from .osdetect import start as start_os_sniffer
from .panel_gate import PanelGateMiddleware

app = FastAPI(title="FORTIS", version="1.0.0", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", settings.public_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def no_store_sensitive_api(request: Request, call_next):
    response = await call_next(request)
    # HTML and unversioned helper scripts must never survive a deployment in cache.
    if not request.url.path.startswith("/assets/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


@app.exception_handler(HTTPException)
async def http_exc(_, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": exc.detail}
    error = {"code": "HTTP", "message": detail.get("message") or "Ошибка запроса"}
    if detail.get("retryAfter"):
        error["retryAfter"] = int(detail["retryAfter"])
    return JSONResponse(status_code=exc.status_code, content={"error": error})


from .setup import router as setup_router
app.include_router(setup_router, prefix="/api")
app.include_router(api, prefix="/api")
app.add_middleware(PanelGateMiddleware, enabled=settings.panel_gate_enabled)
from .http_security import HttpSecurityMiddleware, ClientIpMiddleware, public_hosts
from starlette.middleware.trustedhost import TrustedHostMiddleware
app.add_middleware(HttpSecurityMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=public_hosts(), www_redirect=False)
app.add_middleware(ClientIpMiddleware)

STATIC = Path(__file__).resolve().parent.parent.parent / "web" / "dist"
if STATIC.exists():
    app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def spa(full_path: str, request: Request):
        if full_path.startswith("api/"):
            return JSONResponse({"error": {"code": "NOT_FOUND", "message": "Не найдено"}}, status_code=404)
        index = STATIC / "index.html"
        root = STATIC.resolve()
        file_path = (root / full_path).resolve()
        if not file_path.is_relative_to(root) or any(part.startswith('.') for part in Path(full_path).parts):
            return JSONResponse({"error": {"code": "NOT_FOUND", "message": "Не найдено"}}, status_code=404)
        if full_path and full_path != 'index.html' and file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        base=getattr(request.state,'panel_base','')
        if base:
            html=index.read_text()
            html=html.replace('src="/','src="'+base+'/').replace('href="/','href="'+base+'/')
            html=html.replace('<head>',f'<head><meta name="panel-base" content="{base}"><base href="{base}/">')
            return HTMLResponse(html,headers={'Cache-Control':'no-store'})
        return FileResponse(index)


def _expiry_job():
    with SessionLocal() as db:
        _expire_access(db)


def _presence_job():
    from .presence import sample_presence
    with SessionLocal() as db:
        sample_presence(db)


def _watchdog_job():
    db = SessionLocal()
    try:
        watchdog_tick(db)
    finally:
        db.close()


def _audit_retention_job():
    from .audit import prune_audit_logs
    with SessionLocal() as db:
        prune_audit_logs(db)
        db.commit()


def _ad_sync_job():
    db = SessionLocal()
    try:
        from .ad import sync_if_due
        # The scheduler owns the cadence; do not skip a run due to clock jitter.
        sync_if_due(db, interval_seconds=0)
    except Exception as exc:
        db.rollback()
        logging.getLogger(__name__).warning("Automatic AD sync failed (%s)", type(exc).__name__)
    finally:
        db.close()


def _metrics_job():
    db = SessionLocal()
    try:
        record_host_metrics(db)
    finally:
        db.close()


def _migrate() -> None:
    if engine.dialect.name == "sqlite":
        # First-run SQLite schema is created from the current models.
        return
    statements = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS contact_email TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE sites ADD COLUMN IF NOT EXISTS provider_name TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE sites ADD COLUMN IF NOT EXISTS provider_phone TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE sites ADD COLUMN IF NOT EXISTS provider_email TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_management BOOLEAN NOT NULL DEFAULT false",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS rdp_host TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS rdp_port INTEGER NOT NULL DEFAULT 3389",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS rdp_user TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS rdp_password TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS rdp_save_password BOOLEAN NOT NULL DEFAULT true",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS panel_nonce TEXT DEFAULT ''",
        "ALTER TABLE wireguard_peers ADD COLUMN IF NOT EXISTS destination_cidrs TEXT DEFAULT ''",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS require_agent BOOLEAN DEFAULT true",
        "ALTER TABLE wireguard_peers ADD COLUMN IF NOT EXISTS private_key TEXT DEFAULT ''",
        "ALTER TABLE wireguard_peers ADD COLUMN IF NOT EXISTS client_config TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_confirmed BOOLEAN DEFAULT false",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS ad_guid TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS ad_source TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_by TEXT DEFAULT ''",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS isp TEXT DEFAULT ''",
        "ALTER TABLE wireguard_peers ADD COLUMN IF NOT EXISTS endpoint_trace TEXT DEFAULT '[]'",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS isp TEXT DEFAULT ''",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS mac TEXT DEFAULT ''",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS archived_by TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS ix_security_events_archived_at ON security_events (archived_at)",
        "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS mac TEXT DEFAULT ''",
        "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS browser TEXT DEFAULT ''",
        "ALTER TABLE wireguard_peers ADD COLUMN IF NOT EXISTS link_up BOOLEAN DEFAULT false",
    ]
    with engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))
        from .traffic_counter_migration import migrate_traffic_counters
        migrate_traffic_counters(conn)


@app.on_event("startup")
def startup():
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.ca_dir.mkdir(parents=True, exist_ok=True)
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    _migrate()
    import secrets
    from .models import User
    with SessionLocal() as entry_db:
        for user in entry_db.query(User).filter((User.panel_nonce == '') | (User.panel_nonce.is_(None))).all():
            user.panel_nonce=secrets.token_urlsafe(32)
        entry_db.commit()
    from .setup import completed, load_interfaces, read, activate_interfaces, write
    with SessionLocal() as db:
        from .ad import migrate_secret_storage
        migrate_secret_storage(db)
        load_interfaces(db)
        if completed(db) or read(db, "vpn_ready", False):
            if read(db, "managed", False):
                try:
                    activate_interfaces(db)
                    start_runtime(app)
                except Exception as exc:
                    logging.getLogger(__name__).error("VPN startup failed (%s)", type(exc).__name__)
                    write(db, "completed", False)
                    write(db, "vpn_ready", False)
                    db.commit()
            else:
                start_runtime(app)


def start_runtime(application):
    if getattr(application.state, "scheduler", None):
        return
    db = SessionLocal()
    try:
        refresh_client_configs(db)
        db.commit()
        _expire_access(db)
        restore_enabled_peers(db)
        apply_acl(db)
    finally:
        db.close()
    sched = BackgroundScheduler()
    sched.add_job(_expiry_job, "interval", seconds=1, id="vpn-expiry", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_watchdog_job, "interval", seconds=15, id="wg-watchdog", replace_existing=True)
    sched.add_job(_audit_retention_job, "interval", hours=1, id="audit-retention", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_presence_job, "interval", seconds=2, id="wg-presence", replace_existing=True, max_instances=1, coalesce=True)
    sched.add_job(_metrics_job, "interval", seconds=5, id="host-metrics", replace_existing=True)
    sched.add_job(_ad_sync_job, "interval", seconds=5, id="ad-sync", replace_existing=True, max_instances=1, coalesce=True)
    sched.start()
    application.state.scheduler = sched
    start_os_sniffer()


@app.on_event("shutdown")
def shutdown():
    scheduler = getattr(app.state, "scheduler", None)
    if scheduler:
        scheduler.shutdown(wait=False)


@app.middleware("http")
async def first_run_gate(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and not path.startswith(("/api/setup/", "/api/auth/")):
        from .setup import completed
        with SessionLocal() as db:
            ready = completed(db)
        if not ready:
            return JSONResponse({"error": {"message": "Сначала завершите первичную настройку сервера"}}, status_code=503)
    return await call_next(request)
