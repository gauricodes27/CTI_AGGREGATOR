from .utils import calculate_recency_score

# Stronger weight model
TLP_WEIGHTS = {
    "RED": 50,
    "AMBER": 35,
    "GREEN": 20,
    "WHITE": 10
}

SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 30,
    "Medium": 20,
    "Low": 10
}

CONFIDENCE_WEIGHTS = {
    "High": 20,
    "Medium": 10,
    "Low": 5
}


def classify_risk(score):
    if score >= 85:
        return "Critical"
    elif score >= 65:
        return "High"
    elif score >= 45:
        return "Medium"
    return "Low"


def calculate_threat_score(threat, ioc_count=0, nlp_severity="Medium", confidence="Medium"):
    score = 0

    # 1️⃣ TLP Weight
    tlp = threat.get("tlp", "WHITE").upper()
    score += TLP_WEIGHTS.get(tlp, 10)

    # 2️⃣ Severity Weight
    score += SEVERITY_WEIGHTS.get(nlp_severity, 20)

    # 3️⃣ Confidence Weight
    score += CONFIDENCE_WEIGHTS.get(confidence, 10)

    # 4️⃣ IOC Count Impact (max 25)
    score += min(ioc_count * 6, 25)

    # 5️⃣ Recency Impact (already weighted in utils)
    score += calculate_recency_score(threat.get("created"))

    # Normalize to 100
    final_score = min(score, 100)

    return {
        "score": final_score,
        "risk_level": classify_risk(final_score)
    }
