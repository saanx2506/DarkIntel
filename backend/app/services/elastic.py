"""
Elasticsearch integration for DarkIntel.
Provides: client init, index management, document indexing, and search.
"""

import json
import logging
from datetime import datetime
from elasticsearch import AsyncElasticsearch, NotFoundError
from ..config import settings

logger = logging.getLogger("darkintel.elastic")

# ── Singleton async client ───────────────────────────────────────────────
_es_client: AsyncElasticsearch | None = None


def get_es_client() -> AsyncElasticsearch:
    global _es_client
    if _es_client is None:
        _es_client = AsyncElasticsearch(
            hosts=[settings.ELASTICSEARCH_URL],
            basic_auth=(settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD),
            verify_certs=settings.ELASTICSEARCH_VERIFY_CERTS,
            ssl_show_warn=False,
            request_timeout=30,
        )
    return _es_client


async def close_es_client():
    global _es_client
    if _es_client is not None:
        await _es_client.close()
        _es_client = None


# ── Index names ──────────────────────────────────────────────────────────
IDX_IOCS = "darkintel-iocs"
IDX_EVENTS = "darkintel-events"
IDX_ADVERSARIES = "darkintel-adversaries"


# ── Index mappings ───────────────────────────────────────────────────────
INDEX_SETTINGS = {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "analysis": {
        "analyzer": {
            "ioc_analyzer": {
                "type": "custom",
                "tokenizer": "standard",
                "filter": ["lowercase"],
            }
        }
    },
}

IOC_MAPPING = {
    "properties": {
        "ioc_id": {"type": "integer"},
        "source_id": {"type": "integer"},
        "source_name": {"type": "keyword"},
        "ioc_type": {"type": "keyword"},
        "value": {"type": "text", "analyzer": "ioc_analyzer", "fields": {"raw": {"type": "keyword"}}},
        "threat_type": {"type": "keyword"},
        "malware": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
        "severity": {"type": "float"},
        "first_seen": {"type": "date"},
        "indexed_at": {"type": "date"},
    }
}

EVENT_MAPPING = {
    "properties": {
        "event_id": {"type": "integer"},
        "source_id": {"type": "integer"},
        "source_name": {"type": "keyword"},
        "external_id": {"type": "keyword"},
        "title": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
        "description": {"type": "text"},
        "date": {"type": "keyword"},
        "organization": {"type": "keyword"},
        "threat_level": {"type": "keyword"},
        "tags": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
        "indexed_at": {"type": "date"},
    }
}

ADVERSARY_MAPPING = {
    "properties": {
        "adversary_id": {"type": "integer"},
        "uuid": {"type": "keyword"},
        "name": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
        "description": {"type": "text"},
        "cluster_type": {"type": "keyword"},
        "cluster_name": {"type": "keyword"},
        "country": {"type": "keyword"},
        "state_sponsor": {"type": "keyword"},
        "synonyms": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
        "targets": {"type": "keyword"},
        "incident_type": {"type": "keyword"},
        "indexed_at": {"type": "date"},
    }
}


# ── Index lifecycle ──────────────────────────────────────────────────────
async def ensure_indices():
    """Create indices if they don't exist."""
    es = get_es_client()
    for idx, mapping in [
        (IDX_IOCS, IOC_MAPPING),
        (IDX_EVENTS, EVENT_MAPPING),
        (IDX_ADVERSARIES, ADVERSARY_MAPPING),
    ]:
        if not await es.indices.exists(index=idx):
            await es.indices.create(
                index=idx,
                body={"settings": INDEX_SETTINGS, "mappings": mapping},
            )
            logger.info(f"Created ES index: {idx}")
        else:
            logger.info(f"ES index already exists: {idx}")


# ── Document builders ────────────────────────────────────────────────────
def _ioc_to_doc(ioc, source_name: str = "") -> dict:
    return {
        "ioc_id": ioc.id,
        "source_id": ioc.source_id,
        "source_name": source_name,
        "ioc_type": ioc.ioc_type,
        "value": ioc.value,
        "threat_type": ioc.threat_type,
        "malware": ioc.malware,
        "severity": ioc.severity,
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "indexed_at": datetime.utcnow().isoformat(),
    }


def _event_to_doc(event, source_name: str = "") -> dict:
    return {
        "event_id": event.id,
        "source_id": event.source_id,
        "source_name": source_name,
        "external_id": event.external_id,
        "title": event.title,
        "description": event.description,
        "date": event.date,
        "organization": event.organization,
        "threat_level": event.threat_level,
        "tags": event.tags,
        "indexed_at": datetime.utcnow().isoformat(),
    }


def _adversary_to_doc(adv) -> dict:
    try:
        synonyms = json.loads(adv.synonyms) if adv.synonyms else []
    except Exception:
        synonyms = []
    try:
        targets = json.loads(adv.target_category) if adv.target_category else []
    except Exception:
        targets = []

    return {
        "adversary_id": adv.id,
        "uuid": adv.uuid,
        "name": adv.name,
        "description": adv.description,
        "cluster_type": adv.cluster.cluster_type if adv.cluster else "",
        "cluster_name": adv.cluster.name if adv.cluster else "",
        "country": adv.country,
        "state_sponsor": adv.state_sponsor,
        "synonyms": ", ".join(synonyms) if isinstance(synonyms, list) else str(synonyms),
        "targets": targets,
        "incident_type": adv.incident_type,
        "indexed_at": datetime.utcnow().isoformat(),
    }


# ── Indexing (single docs) ──────────────────────────────────────────────
async def index_ioc(ioc, source_name: str = ""):
    es = get_es_client()
    await es.index(index=IDX_IOCS, id=f"ioc-{ioc.id}", document=_ioc_to_doc(ioc, source_name))


async def index_event(event, source_name: str = ""):
    es = get_es_client()
    await es.index(index=IDX_EVENTS, id=f"event-{event.id}", document=_event_to_doc(event, source_name))


async def index_adversary(adv):
    es = get_es_client()
    await es.index(index=IDX_ADVERSARIES, id=f"adv-{adv.id}", document=_adversary_to_doc(adv))


# ── Bulk indexing (for initial sync) ─────────────────────────────────────
async def bulk_index_iocs(iocs, source_map: dict[int, str] | None = None):
    """Index a list of IOC ORM objects in bulk."""
    es = get_es_client()
    if not iocs:
        return 0
    source_map = source_map or {}
    actions = []
    for ioc in iocs:
        actions.append({"index": {"_index": IDX_IOCS, "_id": f"ioc-{ioc.id}"}})
        actions.append(_ioc_to_doc(ioc, source_map.get(ioc.source_id, "")))
    resp = await es.bulk(operations=actions, refresh="wait_for")
    indexed = sum(1 for item in resp["items"] if item["index"]["status"] in (200, 201))
    logger.info(f"Bulk indexed {indexed} IOCs")
    return indexed


async def bulk_index_events(events, source_map: dict[int, str] | None = None):
    es = get_es_client()
    if not events:
        return 0
    source_map = source_map or {}
    actions = []
    for event in events:
        actions.append({"index": {"_index": IDX_EVENTS, "_id": f"event-{event.id}"}})
        actions.append(_event_to_doc(event, source_map.get(event.source_id, "")))
    resp = await es.bulk(operations=actions, refresh="wait_for")
    indexed = sum(1 for item in resp["items"] if item["index"]["status"] in (200, 201))
    logger.info(f"Bulk indexed {indexed} events")
    return indexed


async def bulk_index_adversaries(adversaries):
    es = get_es_client()
    if not adversaries:
        return 0
    actions = []
    for adv in adversaries:
        actions.append({"index": {"_index": IDX_ADVERSARIES, "_id": f"adv-{adv.id}"}})
        actions.append(_adversary_to_doc(adv))
    resp = await es.bulk(operations=actions, refresh="wait_for")
    indexed = sum(1 for item in resp["items"] if item["index"]["status"] in (200, 201))
    logger.info(f"Bulk indexed {indexed} adversaries")
    return indexed


# ── Full sync from SQLite ────────────────────────────────────────────────
async def full_sync_to_es(db):
    """Bulk-index all IOCs, events, and adversaries from SQLite into ES."""
    from ..models import GenericIOC, IntelEvent, Adversary, SourceConfig

    # Build source name map
    sources = db.query(SourceConfig).all()
    source_map = {s.id: s.name for s in sources}

    # IOCs - batch by 2000
    BATCH = 2000
    total_iocs = db.query(GenericIOC).count()
    ioc_indexed = 0
    for offset in range(0, total_iocs, BATCH):
        batch = db.query(GenericIOC).offset(offset).limit(BATCH).all()
        ioc_indexed += await bulk_index_iocs(batch, source_map)

    # Events
    total_events = db.query(IntelEvent).count()
    event_indexed = 0
    for offset in range(0, total_events, BATCH):
        batch = db.query(IntelEvent).offset(offset).limit(BATCH).all()
        event_indexed += await bulk_index_events(batch, source_map)

    # Adversaries
    adversaries = db.query(Adversary).all()
    adv_indexed = await bulk_index_adversaries(adversaries)

    logger.info(f"Full ES sync complete: {ioc_indexed} IOCs, {event_indexed} events, {adv_indexed} adversaries")
    return {"iocs": ioc_indexed, "events": event_indexed, "adversaries": adv_indexed}


# ── Unified search ───────────────────────────────────────────────────────
async def search_all(query: str, size: int = 50, ioc_type: str | None = None):
    """
    Search across all indices (IOCs, events, adversaries).
    Returns categorised results.
    """
    es = get_es_client()

    # Build the multi-index query
    must = [
        {
            "multi_match": {
                "query": query,
                "fields": [
                    "value^3", "value.raw^5",
                    "title^2", "description",
                    "name^3", "synonyms^2",
                    "malware", "threat_type",
                    "tags", "organization",
                    "country", "state_sponsor", "incident_type",
                ],
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        }
    ]
    filter_clauses = []
    if ioc_type and ioc_type != "all":
        filter_clauses.append({"term": {"ioc_type": ioc_type}})

    body = {
        "query": {
            "bool": {
                "must": must,
                "filter": filter_clauses,
            }
        },
        "size": size,
        "sort": ["_score"],
    }

    resp = await es.search(
        index=f"{IDX_IOCS},{IDX_EVENTS},{IDX_ADVERSARIES}",
        body=body,
    )

    # Categorise hits
    iocs, events, adversaries = [], [], []
    for hit in resp["hits"]["hits"]:
        item = {**hit["_source"], "_score": hit["_score"], "_index": hit["_index"]}
        if hit["_index"] == IDX_IOCS:
            iocs.append(item)
        elif hit["_index"] == IDX_EVENTS:
            events.append(item)
        elif hit["_index"] == IDX_ADVERSARIES:
            adversaries.append(item)

    return {
        "total": resp["hits"]["total"]["value"],
        "iocs": iocs,
        "events": events,
        "adversaries": adversaries,
    }


async def check_es_health() -> dict:
    """Return ES cluster health or error."""
    try:
        es = get_es_client()
        health = await es.cluster.health()
        ioc_count = (await es.count(index=IDX_IOCS))["count"] if await es.indices.exists(index=IDX_IOCS) else 0
        event_count = (await es.count(index=IDX_EVENTS))["count"] if await es.indices.exists(index=IDX_EVENTS) else 0
        adv_count = (await es.count(index=IDX_ADVERSARIES))["count"] if await es.indices.exists(index=IDX_ADVERSARIES) else 0
        return {
            "status": "connected",
            "cluster": health.get("cluster_name"),
            "health": health.get("status"),
            "indices": {
                "iocs": ioc_count,
                "events": event_count,
                "adversaries": adv_count,
            },
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}
