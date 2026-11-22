from datetime import datetime, timezone
import csv, io, httpx
from .base import BaseCollector

CSV_TYPE_MAP = {
    "ip": "ip", "ipv4": "ip", "ipv6": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "uri": "url",
    "md5": "hash", "sha1": "hash", "sha256": "hash", "hash": "hash",
    "email": "email",
}


class CSVFeedCollector(BaseCollector):
    name = "csv_feed"

    def __init__(self, url):
        self.url = url

    async def fetch_raw(self):
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                r = await client.get(self.url)
                if r.status_code != 200:
                    print(f"[csv_feed] fetch failed: {r.status_code}")
                    return []
                reader = csv.DictReader(io.StringIO(r.text))
                return list(reader)
        except Exception as e:
            print(f"[csv_feed] error: {e}")
            return []

    def normalize(self, row: dict):
        ioc_type = CSV_TYPE_MAP.get((row.get("type") or "").strip().lower())
        value = (row.get("value") or "").strip()
        if not ioc_type or not value:
            return None, None
        event_dict = {
            "external_id": f"csv-{self.url}-{value[:32]}",
            "title": f"CSV feed: {self.url}"[:512],
            "description": None,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "organization": "CSV Feed",
            "threat_level": "2",
            "tags": "",
            "galaxies": "",
            "raw_json": str(row),
        }
        ioc_dict = {
            "ioc_type": ioc_type,
            "value": value[:500],
            "threat_type": row.get("threat"),
            "malware": row.get("malware"),
            "first_seen": datetime.now(timezone.utc),
            "raw_json": str(row),
        }
        return event_dict, ioc_dict