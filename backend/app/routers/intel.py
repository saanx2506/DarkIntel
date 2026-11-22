from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from ..database import get_db
from ..models import GenericIOC, IntelEvent, SourceConfig, User
from ..deps import get_current_user
from sqlalchemy import func
from datetime import datetime, timedelta

router = APIRouter(prefix="/api", tags=["intel"])


@router.get("/iocs")
def list_iocs(
    source_id: int | None = None,
    ioc_type: str | None = None,
    min_severity: float = 0.0,
    limit: int = Query(10000, le=50000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(GenericIOC).join(SourceConfig).filter(
        SourceConfig.user_id == user.id,
        GenericIOC.severity >= min_severity,
    )
    if source_id:
        q = q.filter(GenericIOC.source_id == source_id)
    if ioc_type:
        q = q.filter(GenericIOC.ioc_type == ioc_type)
    return q.order_by(desc(GenericIOC.severity)).limit(limit).all()


@router.get("/events")
def list_events(
    source_id: int | None = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(IntelEvent).join(SourceConfig).filter(SourceConfig.user_id == user.id)
    if source_id:
        q = q.filter(IntelEvent.source_id == source_id)
    total = q.count()
    events = q.order_by(desc(IntelEvent.date)).offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total, "page": page, "limit": limit,
        "events": [
            {
                "id": e.id, "external_id": e.external_id, "title": e.title,
                "description": e.description, "date": e.date, "org": e.organization,
                "threat_level": e.threat_level,
                "galaxies": e.galaxies.split(",") if e.galaxies else [],
                "tags": e.tags.split(",") if e.tags else [],
                "attr_count": len(e.iocs),
            } for e in events
        ],
    }


@router.get("/events/{event_id}/iocs")
def event_iocs(event_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ev = db.query(IntelEvent).join(SourceConfig).filter(
        IntelEvent.id == event_id, SourceConfig.user_id == user.id
    ).first()
    if not ev:
        return []
    return [
        {"id": i.id, "ioc_type": i.ioc_type, "value": i.value,
         "severity": i.severity, "malware": i.malware, "threat_type": i.threat_type}
        for i in ev.iocs
    ]


@router.get("/stats")
def stats(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sources = db.query(SourceConfig).filter_by(user_id=user.id).all()
    ids = [s.id for s in sources]
    total_iocs = db.query(GenericIOC).filter(GenericIOC.source_id.in_(ids)).count() if ids else 0
    total_events = db.query(IntelEvent).filter(IntelEvent.source_id.in_(ids)).count() if ids else 0
    high_sev = db.query(GenericIOC).filter(
        GenericIOC.source_id.in_(ids), GenericIOC.severity >= 8
    ).count() if ids else 0
    by_source = {s.name: db.query(GenericIOC).filter_by(source_id=s.id).count() for s in sources}
    return {
        "total_indicators": total_iocs,
        "total_events": total_events,
        "high_severity": high_sev,
        "active_sources": len(sources),
        "by_source": by_source,
    }
     
@router.get("/stats/charts")
def chart_stats(
    days: int = Query(7), # 0 means All Time
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sources = db.query(SourceConfig).filter_by(user_id=user.id).all()
    ids = [s.id for s in sources]
    
    if not ids:
        return {"by_type": [], "by_source": [], "timeline": [], "top_malware": []}

    # Base query with optional time filter
    base_q = db.query(GenericIOC).filter(GenericIOC.source_id.in_(ids))
    if days > 0:
        cutoff = datetime.utcnow() - timedelta(days=days)
        base_q = base_q.filter(GenericIOC.first_seen >= cutoff)

    # 1. IOCs by Type
    by_type = base_q.with_entities(GenericIOC.ioc_type, func.count(GenericIOC.id)) \
        .group_by(GenericIOC.ioc_type).all()
    
    # 2. IOCs by Source
    by_source = base_q.join(SourceConfig).with_entities(SourceConfig.name, func.count(GenericIOC.id)) \
        .group_by(SourceConfig.name).all()

    # 3. Top Malware
    top_malware = base_q.with_entities(GenericIOC.malware, func.count(GenericIOC.id)) \
        .filter(GenericIOC.malware != None) \
        .group_by(GenericIOC.malware) \
        .order_by(func.count(GenericIOC.id).desc()).limit(10).all()

    # 4. Timeline (Dynamic buckets based on days)
    timeline = []
    if days == 0:
        # If All Time, group by month
        raw_timeline = db.query(
            func.strftime('%Y-%m', GenericIOC.first_seen).label('dt'),
            func.count(GenericIOC.id)
        ).filter(GenericIOC.source_id.in_(ids)).group_by('dt').all()
        timeline = [{"date": t[0], "count": t[1]} for t in raw_timeline if t[0]]
    else:
        # If specific days, group by day
        for i in range(days - 1, -1, -1):
            day = (datetime.utcnow() - timedelta(days=i)).date()
            count = base_q.filter(func.date(GenericIOC.first_seen) == day).count()
            timeline.append({"date": day.strftime("%Y-%m-%d"), "count": count})

    return {
        "by_type": [{"name": t[0], "count": t[1]} for t in by_type],
        "by_source": [{"name": t[0], "count": t[1]} for t in by_source],
        "timeline": timeline,
        "top_malware": [{"name": t[0], "count": t[1]} for t in top_malware],
    }