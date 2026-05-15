import requests
import os
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")
BASE_URL = "https://otx.alienvault.com/api/v1/indicators/export"


def fetch_otx_iocs(limit=50):
    if not OTX_API_KEY:
        raise ValueError("OTX_API_KEY not set in environment variables")

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"type": "IPv4", "limit": limit}

    try:
        response = requests.get(BASE_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Error fetching OTX data: {e}")
        return []

    raw_iocs = []

    for item in data.get("results", []):
        indicator = item.get("indicator")
        if indicator:
            raw_iocs.append({
                "ioc_type": "IP",
                "ioc_value": indicator,
                "source": "AlienVault OTX"
            })

    return raw_iocs