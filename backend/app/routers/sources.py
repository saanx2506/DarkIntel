from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
from ..database import get_db
from ..models import SourceConfig, User
from ..deps import get_current_user
from ..collectors import COLLECTOR_REGISTRY, SOURCE_METADATA
from ..services.ingestion import run_ingestion_for_user

router = APIRouter(prefix="/api/sources", tags=["sources"])


class SourceCreate(BaseModel):
    name: str
    source_type: str
    api_url: str | None = None
    api_key: str | None = None
    verify_ssl: bool = True


class SourceOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    name: str
    source_type: str
    api_url: str | None
    verify_ssl: bool
    is_active: bool
    last_sync: datetime | None
    created_at: datetime


@router.get("/available")
def available_sources():
    return SOURCE_METADATA


@router.get("", response_model=list[SourceOut])
def list_sources(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(SourceConfig).filter_by(user_id=user.id).all()


@router.post("", response_model=SourceOut)
def add_source(payload: SourceCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if payload.source_type not in SOURCE_METADATA:
        raise HTTPException(400, f"unsupported source_type: {payload.source_type}")
    meta = SOURCE_METADATA[payload.source_type]
    if meta["requires_url"] and not payload.api_url:
        raise HTTPException(400, "api_url required")
    if meta["requires_key"] and not payload.api_key:
        raise HTTPException(400, "api_key required")
    src = SourceConfig(user_id=user.id, **payload.model_dump())
    db.add(src)
    db.commit()
    db.refresh(src)
    return src


@router.delete("/{source_id}", status_code=204)
def delete_source(source_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    src = db.query(SourceConfig).filter_by(id=source_id, user_id=user.id).first()
    if not src:
        raise HTTPException(404, "not found")
    db.delete(src)
    db.commit()
    return None


@router.post("/sync")
async def sync_all(user: User = Depends(get_current_user)):
    return await run_ingestion_for_user(user.id)


@router.post("/{source_id}/sync")
async def sync_one(source_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    src = db.query(SourceConfig).filter_by(id=source_id, user_id=user.id).first()
    if not src:
        raise HTTPException(404, "not found")
    others = db.query(SourceConfig).filter(
        SourceConfig.user_id == user.id, SourceConfig.id != source_id
    ).all()
    saved = [(o, o.is_active) for o in others]
    for o, _ in saved:
        o.is_active = False
    db.commit()
    try:
        result = await run_ingestion_for_user(user.id)
    finally:
        for o, val in saved:
            o.is_active = val
        db.commit()
    return result