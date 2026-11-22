SEVERITY_WEIGHTS = {
    "c2": 9.0,
    "botnet_cc": 9.0,
    "malware_download": 8.0,
    "ransomware": 9.5,
    "phishing": 6.0,
    "payload_delivery": 7.5,
    "malware": 7.5,
    "campaign": 6.5,
}

def compute_severity(ioc) -> float:
    base = SEVERITY_WEIGHTS.get((ioc.threat_type or "").lower(), 5.0)
    boost = 0.5 if ioc.malware else 0.0
    return round(min(base + boost, 10.0), 2)