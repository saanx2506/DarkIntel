import httpx
import json

async def lookup(term: str, key: str):
    """Pulsedive supports IP, domain, and URL lookups."""
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            "https://pulsedive.com/api/indicator.php",
            params={"indicator": term, "key": key}
        )
        if r.status_code != 200:
            return {"status": "error", "reason": f"HTTP {r.status_code}"}
        
        data = r.json()
        risk = data.get("risk", "unknown")
        threats = data.get("threats", [])
        return {
            "status": "ok",
            "summary": f"Risk: {risk} | Threats: {', '.join(threats) if threats else 'none'}",
            "raw": json.dumps(data)
        }