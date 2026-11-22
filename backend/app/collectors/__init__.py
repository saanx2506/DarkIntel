from .misp import MISPCollector
from .otx import OTXCollector
from .urlhaus import URLhausCollector
from .csv_feed import CSVFeedCollector


COLLECTOR_REGISTRY = {
    "misp":     lambda src: MISPCollector(url=src.api_url, key=src.api_key, verify_ssl=src.verify_ssl),
    "otx":      lambda src: OTXCollector(key=src.api_key),
    "urlhaus":  lambda src: URLhausCollector(key=src.api_key),
    "csv_feed": lambda src: CSVFeedCollector(url=src.api_url),
}


SOURCE_METADATA = {
    "misp": {
        "display_name": "MISP",
        "description": "Malware Information Sharing Platform",
        "requires_url": True,
        "requires_key": True,
        "requires_ssl_toggle": True,
        "category": "feed",
    },
    "otx": {
        "display_name": "AlienVault OTX",
        "description": "Open Threat Exchange community pulses",
        "requires_url": False,
        "requires_key": True,
        "requires_ssl_toggle": False,
        "category": "feed",
    },
    "urlhaus": {
        "display_name": "URLhaus",
        "description": "Malicious URL tracker (abuse.ch) — no key",
        "requires_url": False,
        "requires_key": True,
        "requires_ssl_toggle": False,
        "category": "feed",
    },
    "csv_feed": {
        "display_name": "Custom CSV Feed",
        "description": "CSV with columns: type,value,threat,malware",
        "requires_url": True,
        "requires_key": False,
        "requires_ssl_toggle": False,
        "category": "feed",
    },
    "virustotal": {
        "display_name": "VirusTotal (search)",
        "description": "Multi-engine file/URL/domain scanner — used by the Search page",
        "requires_url": False,
        "requires_key": True,
        "requires_ssl_toggle": False,
        "category": "search",
    },
    "intelx": {
        "display_name": "Intelligence X (search)",
        "description": "Leak & dark web search — used by the Search page",
        "requires_url": False,
        "requires_key": True,
        "requires_ssl_toggle": False,
        "category": "search",
    },
    "pulsedive": {
        "display_name": "Pulsedive (search)",
        "description": "Community threat intel — used by the Search page",
        "requires_url": False,
        "requires_key": True,
        "requires_ssl_toggle": False,
        "category": "search",
    },
    "abuseipdb": {
        "display_name": "AbuseIPDB (search)",
        "description": "IP reputation lookup",
        "requires_url": False,
        "requires_key": True,
        "requires_ssl_toggle": False,
        "category": "search",
    },
}