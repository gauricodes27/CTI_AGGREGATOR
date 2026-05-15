from datetime import datetime


def normalize_iocs(raw_iocs):
    normalized = []

    for ioc in raw_iocs:
        normalized.append({
            "ioc_type": ioc.get("ioc_type"),
            "ioc_value": ioc.get("ioc_value"),
            "category": "malicious_activity",
            "severity": "Medium",
            "confidence": 80,
            "source": ioc.get("source", "Unknown"), 
            "collected_at": datetime.utcnow()
        })

    return normalized
