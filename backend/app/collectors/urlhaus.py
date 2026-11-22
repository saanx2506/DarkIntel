from datetime import datetime, timezone
import json
import httpx
from .base import BaseCollector


class URLhausCollector(BaseCollector):
    name = "urlhaus"

    def __init__(self, key=None):
        self.key = key

    async def fetch_raw(self):
        if not self.key:
            print("[urlhaus] No API key configured.")
            return []

        headers = {"Auth-Key": self.key}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(
                    "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                    headers=headers,
                )
                if r.status_code != 200:
                    print(f"[urlhaus] fetch failed: HTTP {r.status_code}")
                    return []
                data = r.json()
                if data.get("query_status") == "unknown_auth_key":
                    print("[urlhaus] Invalid Auth-Key.")
                    return []
                return data.get("urls", [])
        except Exception as e:
            print(f"[urlhaus] Request error: {e}")
            return []

    def normalize(self, raw: dict):
        tags = raw.get("tags") or []
        tags_str = ",".join(tags) if isinstance(tags, list) else ""

        event_dict = {
            "external_id": f"urlhaus-{raw.get('id', '')}",
            "title": f"URLhaus: {raw.get('threat', 'malware')}"[:512],
            "description": tags_str,
            "date": (raw.get("date_added") or "")[:10],
            "organization": "abuse.ch",
            "threat_level": "2",
            "tags": tags_str,
            "galaxies": "",
            "raw_json": json.dumps(raw, default=str),
        }

        ioc_dict = {
            "ioc_type": "url",
            "value": (raw.get("url") or "")[:500],
            "threat_type": raw.get("threat", "malware"),
            "malware": tags_str[:128] or None,
            "first_seen": datetime.now(timezone.utc),
            "raw_json": json.dumps(raw, default=str),
        }
        return event_dict, ioc_dict