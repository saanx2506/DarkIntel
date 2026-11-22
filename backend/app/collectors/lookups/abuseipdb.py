import httpx
import json

async def lookup(term: str, key: str):
    """AbuseIPDB only supports IP lookups."""
    # Quick IP validation (IPv4 only for simplicity)
    parts = term.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return {"status": "skipped", "reason": "not an IP address"}

    headers = {"Key": key, "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": term, "maxAgeInDays": 90}
        )
        if r.status_code != 200:
            return {"status": "error", "reason": f"HTTP {r.status_code}"}
        
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        return {
            "status": "ok",
            "summary": f"Abuse Score: {score}% | Reports: {data.get('totalReports', 0)}",
            "raw": json.dumps(data)
        }