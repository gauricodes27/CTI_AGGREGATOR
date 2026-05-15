import requests


URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def fetch_urlhaus_iocs(limit=50):
    try:
        response = requests.get(URLHAUS_URL, timeout=10)
        data = response.json()
    except Exception as e:
        print(f"URLhaus fetch error: {e}")
        return []

    raw_iocs = []

    for item in data.get("urls", [])[:limit]:
        raw_iocs.append({
            "ioc_type": "URL",
            "ioc_value": item.get("url"),
            "source": "URLhaus"
        })

    return raw_iocs