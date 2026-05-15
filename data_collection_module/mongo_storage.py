from pymongo import MongoClient, errors
import os
from dotenv import load_dotenv
from risk_scoring_module.scoring_engine import calculate_threat_score

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("MONGO_URI not set in environment variables")

# Create Mongo client
client = MongoClient(MONGO_URI)

# Ensure database is defined in URI like:
# mongodb://localhost:27017/cti_db
db = client.get_default_database()

if db is None:
    raise ValueError("Database name not specified in MONGO_URI")

ioc_collection = db["iocs"]

# Create unique index on ioc_value to prevent duplicates
try:
    ioc_collection.create_index("ioc_value", unique=True)
except Exception as e:
    print(f"Index creation warning: {e}")


def save_iocs(iocs):
    """
    Saves list of IOCs to MongoDB.
    Adds risk score and risk level before inserting.
    """

    if not iocs:
        return 0

    try:
        for threat in iocs:

            # Calculate risk score
            risk_data = calculate_threat_score(
                threat=threat,
                ioc_count=len(iocs),
                nlp_severity=threat.get("severity", "Medium"),
                confidence=threat.get("confidence", "Medium")
            )

            # Attach risk data to threat document
            threat["risk_score"] = risk_data["score"]
            threat["risk_level"] = risk_data["risk_level"]

        result = ioc_collection.insert_many(iocs, ordered=False)
        return len(result.inserted_ids)

    except errors.BulkWriteError as bwe:
        inserted = bwe.details.get("nInserted", 0)
        return inserted

    except Exception as e:
        print(f"Error inserting IOCs: {e}")
        return 0
    