import json
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_
from ..database import get_db
from ..models import GalaxyCluster, Adversary, GalaxySyncState, User
from ..deps import get_current_user
from ..services.galaxy_sync import sync_galaxy_from_github, get_or_create_sync_state

router = APIRouter(prefix="/api/adversaries", tags=["adversaries"])


@router.get("")
def list_adversaries(
    cluster_type: str | None = None,
    country: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    limit: int = Query(24, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Adversary).join(GalaxyCluster)

    if cluster_type and cluster_type != "all":
        q = q.filter(GalaxyCluster.cluster_type == cluster_type)

    if country and country != "all":
        q = q.filter(Adversary.country == country.upper())

    if search:
        s = f"%{search.strip()}%"
        q = q.filter(
            or_(
                Adversary.name.ilike(s),
                Adversary.description.ilike(s),
                Adversary.synonyms.ilike(s),
                Adversary.state_sponsor.ilike(s),
                Adversary.incident_type.ilike(s),
            )
        )

    total = q.count()
    items = q.order_by(Adversary.name.asc()).offset((page - 1) * limit).limit(limit).all()

    # Get clusters with element counts
    clusters_data = []
    total_all = db.query(Adversary).count()
    clusters = db.query(GalaxyCluster).all()
    for c in clusters:
        clusters_data.append({
            "cluster_type": c.cluster_type,
            "name": c.name,
            "count": c.elements_count,
            "version": c.version,
        })

    # Get sync state
    sync_state = get_or_create_sync_state(db)

    serialized = []
    for a in items:
        try:
            synonyms = json.loads(a.synonyms) if a.synonyms else []
        except Exception:
            synonyms = []
        try:
            targets = json.loads(a.target_category) if a.target_category else []
        except Exception:
            targets = []
        try:
            refs = json.loads(a.refs) if a.refs else []
        except Exception:
            refs = []

        serialized.append({
            "id": a.id,
            "uuid": a.uuid,
            "name": a.name,
            "cluster_type": a.cluster.cluster_type if a.cluster else "threat-actor",
            "cluster_name": a.cluster.name if a.cluster else "Threat Actor",
            "description": a.description,
            "country": a.country,
            "state_sponsor": a.state_sponsor,
            "synonyms": synonyms,
            "targets": targets,
            "incident_type": a.incident_type,
            "refs_count": len(refs),
        })

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "total_all": total_all,
        "adversaries": serialized,
        "clusters": clusters_data,
        "sync_state": {
            "repo": sync_state.repo,
            "branch": sync_state.branch,
            "commit_sha": sync_state.last_commit_sha,
            "commit_date": sync_state.last_commit_date,
            "commit_message": sync_state.last_commit_message,
            "last_synced_at": sync_state.last_synced_at.isoformat() if sync_state.last_synced_at else None,
            "is_syncing": sync_state.is_syncing,
            "status": sync_state.status,
        },
    }


@router.get("/sync-status")
def get_sync_status(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sync_state = get_or_create_sync_state(db)
    total_adversaries = db.query(Adversary).count()
    return {
        "repo": sync_state.repo,
        "branch": sync_state.branch,
        "commit_sha": sync_state.last_commit_sha,
        "commit_date": sync_state.last_commit_date,
        "commit_message": sync_state.last_commit_message,
        "last_synced_at": sync_state.last_synced_at.isoformat() if sync_state.last_synced_at else None,
        "is_syncing": sync_state.is_syncing,
        "status": sync_state.status,
        "total_adversaries": total_adversaries,
    }


@router.post("/sync")
async def trigger_sync(
    force: bool = Query(False),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = await sync_galaxy_from_github(db, force=force)
    return result


@router.get("/{adversary_id}")
def get_adversary_detail(
    adversary_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    adv = db.query(Adversary).filter_by(id=adversary_id).first()
    if not adv:
        raise HTTPException(status_code=404, detail="Adversary not found")

    try:
        synonyms = json.loads(adv.synonyms) if adv.synonyms else []
    except Exception:
        synonyms = []
    try:
        targets = json.loads(adv.target_category) if adv.target_category else []
    except Exception:
        targets = []
    try:
        refs = json.loads(adv.refs) if adv.refs else []
    except Exception:
        refs = []
    try:
        meta = json.loads(adv.meta_json) if adv.meta_json else {}
    except Exception:
        meta = {}

    return {
        "id": adv.id,
        "uuid": adv.uuid,
        "name": adv.name,
        "cluster_type": adv.cluster.cluster_type if adv.cluster else "threat-actor",
        "cluster_name": adv.cluster.name if adv.cluster else "Threat Actor",
        "description": adv.description,
        "country": adv.country,
        "state_sponsor": adv.state_sponsor,
        "synonyms": synonyms,
        "targets": targets,
        "incident_type": adv.incident_type,
        "refs": refs,
        "meta": meta,
        "updated_at": adv.updated_at.isoformat() if adv.updated_at else None,
    }
