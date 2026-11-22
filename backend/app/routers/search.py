from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..database import get_db
from ..models import SearchQuery, SearchResult, User
from ..deps import get_current_user
from ..services.lookup_service import run_search

router = APIRouter(prefix="/api/search", tags=["search"])

class SearchRequest(BaseModel):
    term: str

@router.post("")
async def search(payload: SearchRequest, user: User = Depends(get_current_user)):
    if not payload.term.strip():
        raise HTTPException(400, "term is required")
    query_id = await run_search(user.id, payload.term.strip())
    return {"query_id": query_id}

@router.get("/{query_id}")
def get_results(query_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(SearchQuery).filter_by(id=query_id, user_id=user.id).first()
    if not query:
        raise HTTPException(404, "query not found")
    
    results = db.query(SearchResult).filter_by(query_id=query_id).all()
    return {
        "term": query.term,
        "created_at": query.created_at,
        "results": [
            {
                "provider": r.provider,
                "status": r.status,
                "summary": r.summary,
                "raw_json": r.raw_json
            } for r in results
        ]
    }