from pymongo import MongoClient

client = MongoClient(
    "mongodb+srv://sakshidb:cyberthreatintelligence@cticluster.msfa905.mongodb.net/?retryWrites=true&w=majority"
)

print("Connected!")
print(client.list_database_names())

