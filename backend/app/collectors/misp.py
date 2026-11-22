from datetime import datetime, timezone
import asyncio, json
from .base import BaseCollector

MISP_TYPE_MAP = {
    "ip-dst": "ip", "ip-src": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "link": "url",
    "md5": "hash", "sha1": "hash", "sha256": "hash",
    "email-src": "email", "email-dst": "email",
}


class MISPCollector(BaseCollector):
    name = "misp"

    def __init__(self, url, key, verify_ssl=True, lookback_days=7):
        self.url = url
        self.key = key
        self.verify_ssl = verify_ssl
        self.lookback_days = lookback_days

    async def fetch_raw(self):
        return await asyncio.to_thread(self._fetch_sync)

    def _fetch_sync(self):
        from pymisp import PyMISP
        try:
            misp = PyMISP(self.url, self.key, ssl=self.verify_ssl)
            attrs = misp.search(
                controller="attributes",
                published=True,
                to_ids=True,
                last=f"{self.lookback_days}d",
                pythonify=True,
            )
            return [a.to_dict() for a in attrs]
        except Exception as e:
            print(f"[misp] fetch failed: {e}")
            return []

    def normalize(self, raw: dict):
        event_data = raw.get("Event", {})
        event_dict = None
        if event_data:
            org = event_data.get("Orgc", {})
            event_dict = {
                "external_id": str(event_data.get("id", "")),
                "title": event_data.get("info", "Unnamed Event")[:512],
                "description": None,
                "date": event_data.get("date"),
                "organization": org.get("name") if isinstance(org, dict) else "Unknown",
                "threat_level": str(event_data.get("threat_level_id", "4")),
                "tags": ",".join([t.get("name", "") for t in event_data.get("Tag", []) if t.get("name")]),
                "galaxies": ",".join([g.get("name", "") for g in event_data.get("Galaxy", []) if g.get("name")]),
                "raw_json": json.dumps(event_data, default=str),
            }

        ioc_dict = None
        ioc_type = MISP_TYPE_MAP.get(raw.get("type", ""))
        if ioc_type and raw.get("value"):
            first_seen = None
            if raw.get("timestamp"):
                try:
                    first_seen = datetime.fromtimestamp(int(raw["timestamp"]), tz=timezone.utc)
                except Exception:
                    pass
            tags = [t.get("name", "") for t in raw.get("Tag", []) if t.get("name")]
            malware = next(
                (t.split("=")[-1].split('"')[0][:128] for t in tags if "malware" in t.lower()),
                None,
            )
            ioc_dict = {
                "ioc_type": ioc_type,
                "value": raw["value"][:500],
                "threat_type": (raw.get("category") or "Uncategorized")[:128],
                "malware": malware,
                "first_seen": first_seen,
                "raw_json": json.dumps(raw, default=str),
            }
        return event_dict, ioc_dict