import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from .config import settings
from .database import Base, engine, SessionLocal
from .models import User
from .security import hash_password
from .routers import auth, sources, intel, search, adversaries
from .services.ingestion import run_ingestion_for_user


async def _background_galaxy_check():
    await asyncio.sleep(1)
    db = SessionLocal()
    try:
        from .models import Adversary
        if db.query(Adversary).count() == 0:
            print("[galaxy_sync] No adversaries found in DB. Ingesting MISP Galaxy clusters from GitHub...")
            from .services.galaxy_sync import sync_galaxy_from_github
            await sync_galaxy_from_github(db, force=False)
            print("[galaxy_sync] Initial MISP Galaxy sync completed.")
    except Exception as e:
        print(f"[galaxy_sync] Startup sync check error: {e}")
    finally:
        db.close()


async def _background_es_init():
    """Initialize ES indices and run a full sync if indices are empty."""
    await asyncio.sleep(3)
    try:
        from .services.elastic import ensure_indices, check_es_health, full_sync_to_es
        await ensure_indices()
        health = await check_es_health()
        if health.get("status") == "connected":
            counts = health.get("indices", {})
            if counts.get("iocs", 0) == 0:
                print("[es-init] Empty ES indices detected. Running full sync from SQLite...")
                db = SessionLocal()
                try:
                    result = await full_sync_to_es(db)
                    print(f"[es-init] Full sync done: {result}")
                finally:
                    db.close()
            else:
                print(f"[es-init] ES connected. Indices: {counts}")
        else:
            print(f"[es-init] ES not available: {health.get('detail', 'unknown')}")
    except Exception as e:
        print(f"[es-init] ES init error (non-fatal): {e}")


def _seed_admin():
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.role == "admin").first():
            admin = User(
                email=settings.SEED_ADMIN_EMAIL,
                hashed_password=hash_password(settings.SEED_ADMIN_PASSWORD),
                full_name="Administrator",
                role="admin",
            )
            db.add(admin)
            db.commit()
            print(f"[seed] created admin {admin.email}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    _seed_admin()
    asyncio.create_task(_background_galaxy_check())
    asyncio.create_task(_background_es_init())
    yield
    # Cleanup ES client on shutdown
    try:
        from .services.elastic import close_es_client
        await close_es_client()
    except Exception:
        pass


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    # Prevent browser from aggressively caching static assets
    if request.url.path.endswith((".css", ".js", ".html")) or request.url.path == "/":
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

app.include_router(auth.router)
app.include_router(sources.router)
app.include_router(intel.router)
app.include_router(search.router)
app.include_router(adversaries.router)

from .routers import es_search
app.include_router(es_search.router)

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
INDEX_HTML = FRONTEND_DIR / "index.html"

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
app.mount("/app.css", StaticFiles(directory=str(FRONTEND_DIR)), name="css")
app.mount("/app.js", StaticFiles(directory=str(FRONTEND_DIR)), name="js")

@app.get("/")
def serve_index():
    return FileResponse(str(INDEX_HTML))


@app.get("/{full_path:path}")
def catch_all(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404)
    return FileResponse(str(INDEX_HTML))