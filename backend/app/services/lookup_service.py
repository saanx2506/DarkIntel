import asyncio
from sqlalchemy.orm import Session
from ..database import SessionLocal
from ..models import SearchQuery, SearchResult, SourceConfig
from ..collectors.lookups import abuseipdb, virustotal, intelx, pulsedive

PROVIDERS = {
    "abuseipdb": abuseipdb.lookup,
    "virustotal": virustotal.lookup,
    "intelx": intelx.lookup,
    "pulsedive": pulsedive.lookup,
}

async def run_search(user_id: int, term: str):
    db: Session = SessionLocal()
    
    # 1. Create the query record
    query = SearchQuery(user_id=user_id, term=term)
    db.add(query)
    db.commit()
    db.refresh(query)
    
    # 2. Find which providers the user has configured keys for
    sources = db.query(SourceConfig).filter(
        SourceConfig.user_id == user_id,
        SourceConfig.source_type.in_(PROVIDERS.keys()),
        SourceConfig.is_active == True
    ).all()
    
    # 3. Run all lookups in parallel
    tasks = []
    for src in sources:
        provider_func = PROVIDERS.get(src.source_type)
        if provider_func:
            tasks.append((src.source_type, provider_func(term, src.api_key)))
    
    results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
    
    # 4. Save results
    for (provider_name, _), result in zip(tasks, results):
        if isinstance(result, Exception):
            result = {"status": "error", "reason": str(result)}
        
        db.add(SearchResult(
            query_id=query.id,
            provider=provider_name,
            status=result.get("status", "error"),
            summary=result.get("summary"),
            raw_json=result.get("raw")
        ))
    
    db.commit()
    query_id = query.id  # <-- capture BEFORE closing the session
    db.close()
    return query_id