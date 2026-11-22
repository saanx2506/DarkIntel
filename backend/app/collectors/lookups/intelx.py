import httpx
import json
import asyncio

async def lookup(term: str, key: str):
    """IntelX supports almost any selector (IP, domain, email, etc.)."""
    headers = {"x-key": key, "Content-Type": "application/json"}
    payload = {"term": term, "maxresults": 10, "media": 0}
    
    async with httpx.AsyncClient(timeout=30) as client:
        # Start search
        r = await client.post("https://free.intelx.io/intelligent/search", headers=headers, json=payload)
        if r.status_code != 200:
            return {"status": "error", "reason": f"HTTP {r.status_code}"}
        
        search_id = r.json().get("id")
        if not search_id:
            return {"status": "ok", "summary": "No search ID returned", "raw": "{}"}
        
        # Poll for results (simple 2s wait)
        await asyncio.sleep(2)
        res = await client.get(
            "https://free.intelx.io/intelligent/search/result",
            headers=headers, params={"id": search_id, "limit": 10}
        )
        if res.status_code != 200:
            return {"status": "error", "reason": f"Poll HTTP {res.status_code}"}
        
        records = res.json().get("records", [])
        return {
            "status": "ok",
            "summary": f"Found {len(records)} leak/darkweb records",
            "raw": json.dumps(records)
        }