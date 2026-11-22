import httpx
import json

async def lookup(term: str, key: str):
    """VirusTotal supports IP, domain, URL, and hash lookups."""
    # Determine the endpoint based on the term
    base = "https://www.virustotal.com/api/v3"
    
    if term.startswith("http"):
        endpoint = f"{base}/urls/{term}"
    elif len(term) in (32, 40, 64) and all(c in "0123456789abcdef" for c in term.lower()):
        endpoint = f"{base}/files/{term}"
    elif term.replace(".", "").isdigit():
        endpoint = f"{base}/ip_addresses/{term}"
    else:
        endpoint = f"{base}/domains/{term}"

    headers = {"x-apikey": key}
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(endpoint, headers=headers)
        if r.status_code == 404:
            return {"status": "ok", "summary": "Not found in VirusTotal", "raw": "{}"}
        if r.status_code != 200:
            return {"status": "error", "reason": f"HTTP {r.status_code}"}
        
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return {
            "status": "ok",
            "summary": f"Malicious: {malicious} | Suspicious: {suspicious}",
            "raw": json.dumps(data)
        }