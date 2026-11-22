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
from .routers import auth, sources, intel
from .services.ingestion import run_ingestion_for_user
from .routers import auth, sources, intel, search


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
    yield


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(sources.router)
app.include_router(intel.router)
app.include_router(search.router)

app.mount("/app.css", StaticFiles(directory="../frontend"), name="css")
app.mount("/app.js", StaticFiles(directory="../frontend"), name="js")

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
def serve_index():
    return FileResponse("../frontend/index.html")


@app.get("/{full_path:path}")
def catch_all(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404)
    return FileResponse("../frontend/index.html")