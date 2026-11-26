from fastapi import APIRouter, Depends, Query, HTTPException
from ..deps import get_current_user
from ..models import User
from ..database import get_db
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/es", tags=["elasticsearch"])


@router.get("/search")
async def es_search(
    q: str = Query(..., min_length=1, description="Search query"),
    type: str = Query("all", description="Filter by IOC type (ip, url, domain, hash) or 'all'"),
    size: int = Query(50, ge=1, le=200),
    user: User = Depends(get_current_user),
):
    """Search across IOCs, events, and adversaries using Elasticsearch."""
    from ..services.elastic import search_all
    try:
        results = await search_all(query=q, size=size, ioc_type=type if type != "all" else None)
        return results
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Elasticsearch unavailable: {str(e)}")


@router.get("/health")
async def es_health(user: User = Depends(get_current_user)):
    """Return Elasticsearch cluster health and index doc counts."""
    from ..services.elastic import check_es_health
    return await check_es_health()


@router.post("/sync")
async def es_full_sync(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Trigger a full re-index from SQLite into Elasticsearch."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    from ..services.elastic import full_sync_to_es
    try:
        result = await full_sync_to_es(db)
        return {"status": "ok", "indexed": result}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"ES sync failed: {str(e)}")
