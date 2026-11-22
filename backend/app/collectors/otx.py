from datetime import datetime, timezone
import json, httpx
from .base import BaseCollector

OTX_TYPE_MAP = {
    "IPv4": "ip", "IPv6": "ip",
    "domain": "domain", "hostname": "domain",
    "URL": "url", "URI": "url",
    "FileHash-MD5": "hash", "FileHash-SHA1": "hash", "FileHash-SHA256": "hash",
    "email": "email",
}


class OTXCollector(BaseCollector):
    name = "otx"

    def __init__(self, key, lookback_days=7):
        self.key = key

    async def fetch_raw(self):
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(
                    "https://otx.alienvault.com/api/v1/pulses/subscribed",
                    headers={"X-OTX-API-KEY": self.key},
                    params={"limit": 50, "page": 1},
                )
                if r.status_code != 200:
                    print(f"[otx] fetch failed: {r.status_code}")
                    return []
                return r.json().get("results", [])
        except Exception as e:
            print(f"[otx] error: {e}")
            return []

    def normalize(self, pulse: dict):
        event_dict = {
            "external_id": pulse.get("id", ""),
            "title": pulse.get("name", "Unnamed Pulse")[:512],
            "description": (pulse.get("description") or "")[:2000],
            "date": (pulse.get("modified") or "")[:10],
            "organization": pulse.get("author_name", "Unknown"),
            "threat_level": "2",
            "tags": ",".join(pulse.get("tags", [])),
            "galaxies": ",".join(pulse.get("malware_families", [])),
            "raw_json": json.dumps(pulse, default=str),
        }
        iocs = pulse.get("indicators", [])
        if not iocs:
            return event_dict, None
        ind = iocs[0]
        ioc_type = OTX_TYPE_MAP.get(ind.get("type", ""))
        if not ioc_type:
            return event_dict, None
        return event_dict, {
            "ioc_type": ioc_type,
            "value": (ind.get("indicator") or "")[:500],
            "threat_type": "malware",
            "malware": ", ".join(pulse.get("malware_families", []))[:128] or None,
            "first_seen": datetime.now(timezone.utc),
            "raw_json": json.dumps(ind, default=str),
        }