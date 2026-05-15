from .otx_fetcher import fetch_otx_iocs
from .urlhaus_fetcher import fetch_urlhaus_iocs
from .normalizer import normalize_iocs
from .mongo_storage import save_iocs


def collect_all_data():
    raw_data = []

    raw_data.extend(fetch_otx_iocs())
    raw_data.extend(fetch_urlhaus_iocs())

    normalized = normalize_iocs(raw_data)
    inserted = save_iocs(normalized)

    return {
        "fetched": len(raw_data),
        "inserted": inserted
    }