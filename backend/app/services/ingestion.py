from datetime import datetime
from sqlalchemy.orm import Session
from ..database import SessionLocal
from ..models import SourceConfig, IntelEvent, GenericIOC
from ..collectors import COLLECTOR_REGISTRY
from .enrichment import compute_severity

# These are used by the Search page, not the ingestion loop
SEARCH_ONLY_PROVIDERS = {"abuseipdb", "virustotal", "intelx", "pulsedive"}


async def run_ingestion_for_user(user_id: int):
    db: Session = SessionLocal()
    sources = db.query(SourceConfig).filter_by(user_id=user_id, is_active=True).all()
    total_events, total_iocs = 0, 0

    if not sources:
        print("[ingestion] No active sources configured.")
        db.close()
        return {"events": 0, "iocs": 0}

    for src in sources:
        # Skip search-only providers (they're queried by /api/search, not synced)
        if src.source_type in SEARCH_ONLY_PROVIDERS:
            continue

        factory = COLLECTOR_REGISTRY.get(src.source_type)
        if not factory:
            print(f"[ingestion] Unsupported source type: {src.source_type}")
            continue

        print(f"[ingestion] Running: {src.name} ({src.source_type})")

        # 1. Fetch Data
        try:
            collector = factory(src)
            items = await collector.collect()
        except Exception as e:
            print(f"[{src.name}] Collector failed: {e}")
            src.last_sync = datetime.utcnow()
            db.commit()
            continue

        # 2. Process Items
        for event_dict, ioc_dict in items:
            event_obj = None

            if event_dict and event_dict.get("external_id"):
                existing_event = db.query(IntelEvent).filter_by(
                    source_id=src.id, external_id=event_dict["external_id"]
                ).first()

                if existing_event:
                    event_obj = existing_event
                else:
                    event_obj = IntelEvent(source_id=src.id, **event_dict)
                    db.add(event_obj)
                    db.flush()
                    total_events += 1

            if ioc_dict and ioc_dict.get("value"):
                exists = db.query(GenericIOC).filter_by(
                    source_id=src.id,
                    ioc_type=ioc_dict["ioc_type"],
                    value=ioc_dict["value"],
                ).first()

                if not exists:
                    ioc = GenericIOC(
                        source_id=src.id,
                        event_id=event_obj.id if event_obj else None,
                        **ioc_dict,
                    )
                    ioc.severity = compute_severity(ioc)
                    db.add(ioc)
                    total_iocs += 1

        # 3. Update timestamp and commit (runs even if 0 items)
        src.last_sync = datetime.utcnow()
        db.commit()

    db.close()
    print(f"[ingestion] Finished. New Events: {total_events}, New IOCs: {total_iocs}")
    return {"events": total_events, "iocs": total_iocs}