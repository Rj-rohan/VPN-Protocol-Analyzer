import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.api import analysis, auth, captures, compliance, health, live, reports
from app.config import settings
from app.core.models import Role, User
from app.core.security import hash_password
from app.db.database import SessionLocal, init_db
from app.packet.tshark import TSharkService
from app.worker import get_queue

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ipsec_analyzer")


def bootstrap_admin() -> None:
    """Create the first administrator from ADMIN_EMAIL / ADMIN_PASSWORD when no user exists."""
    with SessionLocal() as db:
        if db.scalar(select(User.id).limit(1)):
            return
        if not (settings.admin_email and settings.admin_password):
            logger.warning("No users exist. Set ADMIN_EMAIL and ADMIN_PASSWORD, or run `python -m app.cli create-user`.")
            return
        db.add(User(email=settings.admin_email.strip().lower(), full_name="Administrator",
                    password_hash=hash_password(settings.admin_password), role=Role.admin))
        db.commit()
        logger.info("Created initial administrator %s", settings.admin_email)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not settings.jwt_secret:
        logger.warning("JWT_SECRET is not set; using a random per-process secret, so sessions end when the server restarts.")
    init_db()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    bootstrap_admin()
    TSharkService().capabilities()  # probe version and supported fields once, before the first upload
    resumed = get_queue().resume_pending()
    if resumed:
        logger.info("Resumed %d interrupted analyses", resumed)
    yield
    get_queue().shutdown()


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


app.include_router(health.router)
app.include_router(auth.router)
app.include_router(captures.router)
app.include_router(analysis.router)
app.include_router(reports.router)
app.include_router(live.router)
app.include_router(compliance.router)
