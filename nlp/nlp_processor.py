from datetime import datetime
from .ioc_extractor import extract_iocs

THREAT_KEYWORDS = {
    "Ransomware": ["ransomware", "encrypt", "bitcoin"],
    "Phishing": ["phishing", "fake login", "credential"],
    "Malware": ["malware", "trojan", "virus"],
}

def classify_threat(text):
    for category, words in THREAT_KEYWORDS.items():
        if any(word.lower() in text.lower() for word in words):
            return category
    return "Unknown"

def severity_score(iocs):
    score = len(iocs["ips"]) + len(iocs["domains"]) + len(iocs["hashes"])
    if score >= 5:
        return "High"
    elif score >= 2:
        return "Medium"
    return "Low"

def analyze_text(text, source):
    iocs = extract_iocs(text)
    return {
        "source": source,
        "category": classify_threat(text),
        "severity": severity_score(iocs),
        "iocs": iocs,
        "summary": text[:180] + "...",
        "timestamp": datetime.utcnow()
    }


def save_nlp_result(result, collection):
    doc = {
        "category": result.get("category"),
        "severity": result.get("severity"),
        "summary": result.get("summary"),
        "iocs": {
            "ips": result.get("ips", []),
            "domains": result.get("domains", []),
            "hashes": result.get("hashes", [])
        },
        "timestamp": datetime.utcnow()
    }

    collection.insert_one(doc)
