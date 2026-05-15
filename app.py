import os
import json
import certifi
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, send_from_directory, url_for, session, jsonify
from datetime import datetime, timezone
from itsdangerous import URLSafeTimedSerializer
from collections import Counter
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient 
import requests
from bson import ObjectId
import textwrap
from data_collection_module import collect_all_data
from risk_scoring_module import calculate_threat_score
from data_collection_module.mongo_storage import ioc_collection
import os
import re

def is_strong_password(password):
    """
    At least 8 characters
    1 uppercase
    1 lowercase
    1 digit
    1 special character
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True

def extract_iocs(text):
    if not text:
        return {"ip": [], "domain": [], "hash": []}

    text = text.replace("[.]", ".").replace("hxxp", "http")

    return {
        "ip": list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))),
        "domain": list(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text))),
        "hash": list(set(re.findall(r"\b[a-fA-F0-9]{32,64}\b", text)))
    }




# Load environment variables
load_dotenv()

app = Flask(__name__)

secret = os.getenv("SECRET_KEY")

if not secret:
    raise ValueError("SECRET_KEY is not set in environment variables.")

app.secret_key = secret

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


client = MongoClient(
    os.getenv("MONGO_URI"),
    tls=True,
    tlsCAFile=certifi.where()
)



db = client["cti_db"]   # ✅ define db FIRST

# 🆕 NLP Collection (SAFE – NEW ONLY)
nlp_collection = db["nlp_analysis"]


print("Databases:", client.list_database_names())
print("Collections:", db.list_collection_names())

print("✅ Connected DBs:", client.list_database_names())



# Test connection
print("✅ Connected DBs:", client.list_database_names())

db = client["cti_db"]
users = db["users"]
threats = db["threat_feeds"]
reports_col = db["reports"]
iocs_col = db["iocs"]


from datetime import datetime

def generate_reports_from_threats():
    try:
        # Fetch recent threats
        recent_threats = threats.find().sort("_id", -1).limit(20)

        for t in recent_threats:
            base_title = t.get("title") or "Untitled Threat"
            description = t.get("description") or ""

            # Ensure tags exist before using
            tags = t.get("tags") or ["general"]

            # 🧠 NLP ANALYSIS (STEP 4)
            if description.strip():
                try:
                    iocs = extract_iocs(description) or {}

                    # 🔥 ADD THIS BLOCK JUST BELOW IT
                    extra_ips = []
                    extra_domains = []
                    extra_hashes = []

                    for ind in t.get("indicators", []):
                        ind_type = ind.get("type", "").lower()
                        ind_value = ind.get("indicator")

                        if not ind_value:
                            continue

                        if "ipv4" in ind_type or ind_type == "ip":
                            extra_ips.append(ind_value)

                        elif "domain" in ind_type or "hostname" in ind_type:
                            extra_domains.append(ind_value)

                        elif "hash" in ind_type:
                            extra_hashes.append(ind_value)

                    # 🔥 MERGE BOTH SOURCES
                    iocs["ip"] = list(set(iocs.get("ip", []) + extra_ips))
                    iocs["domain"] = list(set(iocs.get("domain", []) + extra_domains))
                    iocs["hash"] = list(set(iocs.get("hash", []) + extra_hashes))
                except Exception as e:
                    print(f"⚠️ IOC extraction failed for threat '{base_title}': {e}")
                    iocs = {}

                nlp_doc = {
                    "tags": tags,
                    "category": tags[0] if tags else "Unknown",
                    "severity": "High" if t.get("tlp") in ["RED", "AMBER"] else "Medium",
                    "summary": description[:300],
                    "iocs": {
                        "ips": iocs.get("ip", []),
                        "domains": iocs.get("domain", []),
                        "hashes": iocs.get("hash", [])
                    },
                    "timestamp": t.get("created") or datetime.utcnow()
                }

                try:
                    nlp_collection.insert_one(nlp_doc)
                except Exception as e:
                    print(f"❌ Failed to insert NLP doc for threat '{base_title}': {e}")

            # 🔥 SAME THREAT → MANY REPORTS
            for tag in tags:
                report_title = f"{base_title} | Analysis: {tag}"

                # Avoid duplicate (threat + tag)
                if reports_col.find_one({"title": report_title}):
                    continue

                try:
                    reports_col.insert_one({
                        "title": report_title,
                        "summary": f"{tag.upper()} related threat detected. " + description[:150] + "...",
                        "details": description,
                        "category": tag,
                        "author": t.get("author") or "Unknown",
                        "created": t.get("created") or datetime.utcnow(),
                        "source": "AlienVault OTX",
                        "generated_at": datetime.utcnow()
                    })
                except Exception as e:
                    print(f"❌ Failed to insert report for threat '{base_title}': {e}")

    except Exception as e:
        print(f"❌ Error generating threat reports: {e}")


def ensure_threat_data():
    try:
        OTX_API_KEY = os.getenv("OTX_API_KEY")
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        for pulse in data.get("results", []):

            title = pulse.get("name")
            description = pulse.get("description") or ""

            if not title:
                continue

            # 🔥 CHECK IF THREAT EXISTS
            threat = threats.find_one({"title": title})

            if not threat:
                # 🔥 INSERT THREAT
                threat_id = threats.insert_one({
                    "title": title,
                    "description": description,
                    "author": pulse.get("author_name"),
                    "created": pulse.get("created"),
                    "tlp": pulse.get("tlp", "WHITE"),
                    "tags": pulse.get("tags", []),
                    "source": "AlienVault OTX"
                }).inserted_id
            else:
                threat_id = threat["_id"]
                # 🔥 EXTRACT IOCs FROM OTX INDICATORS (CORRECT WAY)
        indicators = pulse.get("indicators", [])

        for ind in indicators:
            ind_type = ind.get("type", "").lower()
            ind_value = ind.get("indicator")

            if not ind_value:
                continue

            # IP Addresses
            if "ipv4" in ind_type or ind_type == "ip":
                iocs_col.update_one(
                    {"type": "ip", "value": ind_value},
                    {"$setOnInsert": {
                        "type": "ip",
                        "value": ind_value,
                        "threat_id": threat_id,
                        "first_seen": datetime.now(timezone.utc)
                    }},
                    upsert=True
                )

            # Domains / Hostnames
            elif "domain" in ind_type or "hostname" in ind_type:
                iocs_col.update_one(
                    {"type": "domain", "value": ind_value},
                    {"$setOnInsert": {
                        "type": "domain",
                        "value": ind_value,
                        "threat_id": threat_id,
                        "first_seen": datetime.now(timezone.utc)
                    }},
                    upsert=True
                )

            # Hashes
            elif "hash" in ind_type:
                iocs_col.update_one(
                    {"type": "hash", "value": ind_value},
                    {"$setOnInsert": {
                        "type": "hash",
                        "value": ind_value,
                        "threat_id": threat_id,
                        "first_seen": datetime.now(timezone.utc)
                    }},
                    upsert=True
                )


            
        generate_reports_from_threats()

    except Exception as e:
        print("⚠️ Threat fetch failed:", e)

@app.route("/collect")
def collect_data():
    result = collect_all_data()
    return result



from flask import jsonify

@app.route("/api/reports")
def api_reports():
    reports = []
    for r in reports_col.find().sort("_id", -1):

        reports.append({
            "id": str(r["_id"]),
            "title": r.get("title"),
            "summary": r.get("summary"),
            "details": r.get("details"),
            "category": r.get("category"),
            "created": r.get("created")
        })

    return jsonify(reports)

@app.route("/api/threats/risk", methods=["GET"])
def get_risk_data():

    threat_docs = list(threats.find().sort("_id", -1).limit(20))

    result = []

    for t in threat_docs:

        # Count IOCs linked to this threat
        ioc_count = iocs_col.count_documents({"threat_id": t["_id"]})

        # Simple NLP severity logic
        nlp_severity = "High" if t.get("tlp") in ["RED", "AMBER"] else "Medium"

        # 🔥 CALL YOUR SCORING ENGINE
        risk = calculate_threat_score(
            threat=t,
            ioc_count=ioc_count,
            nlp_severity=nlp_severity
        )

        result.append({
            "title": t.get("title", "No Title"),
            "score": risk["score"],
            "level": risk["risk_level"],
            "tlp": t.get("tlp", "WHITE")
        })

    return jsonify(result)

@app.route("/risk_dashboard")
def risk_dashboard():
    return render_template("risk_dashboard.html")


from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from flask import send_file
import io
import textwrap


from flask import Response
import json
import time

@app.route("/api/alerts/stream")
def alert_stream():
    def event_stream():
        last_id = None

        while True:
            query = {}
            if last_id:
                query = {"_id": {"$gt": last_id}}

            new_alerts = threats.find(
                query
            ).sort("_id", 1)

            for alert in new_alerts:
                last_id = alert["_id"]

                if alert.get("tlp") in ["RED", "AMBER"]:
                    data = {
                        "title": alert.get("title"),
                        "source": alert.get("source"),
                        "severity": "ALERT"
                    }

                    yield f"data: {json.dumps(data)}\n\n"

            time.sleep(5)  # check every 5 seconds

    return Response(event_stream(), mimetype="text/event-stream")

import random

@app.route("/api/simulate-alert", methods=["POST"])
def simulate_alert():
    threats.insert_one({
        "title": f"Simulated Threat {datetime.utcnow()}",
        "description": "Simulated real-time alert",
        "author": "CTI Engine",
        "created": datetime.utcnow().isoformat(),
        "tlp": random.choice(["RED", "AMBER"]),
        "tags": ["simulation"],
        "source": "Internal Engine"
    })
    return jsonify({"status": "ok"})


@app.route("/api/reports/pdf/<report_id>")
def export_report_pdf(report_id):

    report = reports_col.find_one({"_id": ObjectId(report_id)})
    if not report:
        return jsonify({"error": "Report not found"}), 404

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    y = height - 60

    # =========================
    # MAIN TITLE
    # =========================
    pdf.setFont("Helvetica-Bold", 18)

    title_text = report.get("title", "Threat Intelligence Report")

    title = pdf.beginText(50, y)
    title.setLeading(22)

    for line in textwrap.wrap(title_text, 55):
        title.textLine(line)
        y -= 24

    pdf.drawText(title)
    y -= 10

    # Divider
    pdf.setStrokeColor(HexColor("#999999"))
    pdf.line(50, y, width - 50, y)
    y -= 25

    
    # =========================
    # METADATA SECTION
    # =========================
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(50, y, "Category:")
    pdf.setFont("Helvetica", 11)
    pdf.drawString(120, y, report.get("category", "N/A"))
    y -= 18

    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(50, y, "Source:")
    pdf.setFont("Helvetica", 11)
    pdf.drawString(120, y, report.get("source", "N/A"))
    y -= 18

    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(50, y, "Created:")
    pdf.setFont("Helvetica", 11)
    pdf.drawString(120, y, str(report.get("created", "N/A")))
    y -= 30

    # =========================
    # SECTION: THREAT OVERVIEW
    # =========================
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Threat Overview")
    y -= 18

    pdf.setFont("Helvetica", 11)
    text = pdf.beginText(50, y)
    text.setLeading(16)

    summary = report.get("summary") or "No summary available."
    for line in textwrap.wrap(summary, 95):
        text.textLine(line)
        y -= 16

    pdf.drawText(text)
    y -= 25

    # =========================
    # SECTION: DETAILED ANALYSIS
    # =========================
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Detailed Analysis")
    y -= 20

    pdf.setFont("Helvetica", 11)
    text = pdf.beginText(50, y)
    text.setLeading(16)

    details = report.get("details") or "No details available."

    wrapped_lines = []
    for para in details.split("\n\n"):
        wrapped_lines.extend(textwrap.wrap(para, 95))
        wrapped_lines.append("")

    for line in wrapped_lines:
        if y < 60:
            pdf.drawText(text)
            pdf.showPage()
            pdf.setFont("Helvetica", 11)
            text = pdf.beginText(50, height - 60)
            text.setLeading(16)
            y = height - 60

        text.textLine(line)
        y -= 16

    pdf.drawText(text)

    # =========================
# FOOTER (CENTER ALIGNED)
# =========================
    footer_text = "Generated by CTI Aggregator • For academic and research purposes only"

    pdf.setFont("Helvetica-Oblique", 9)

    text_width = pdf.stringWidth(footer_text, "Helvetica-Oblique", 9)
    x_center = (width - text_width) / 2

    pdf.drawString(
        x_center,
        40,
        footer_text
    )

    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="CTI_Report.pdf",
        mimetype="application/pdf"
    )



@app.route("/api/stats")
def api_stats():
    OTX_API_KEY = os.getenv("OTX_API_KEY")

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    response = requests.get(url, headers=headers)
    data = response.json()

    category_count = {}
    severity_count = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for pulse in data.get("results", []):
        for tag in pulse.get("tags", []):
            category_count[tag] = category_count.get(tag, 0) + 1

        tlp = pulse.get("tlp", "WHITE")
        if tlp == "RED":
            severity_count["Critical"] += 1
        elif tlp == "AMBER":
            severity_count["High"] += 1
        elif tlp == "GREEN":
            severity_count["Medium"] += 1
        else:
            severity_count["Low"] += 1

    return {
        "categories": category_count,
        "severity": severity_count
    }

from flask import jsonify

@app.route("/api/threat-feed")
def threat_feed():

    stored_threats = threats.find().sort("_id", -1).limit(20)

    feeds = []
    for t in stored_threats:
        feeds.append({
            "title": t["title"],
            "description": t.get("description"),
            "author": t.get("author"),
            "created": t.get("created"),
            "tlp": t.get("tlp"),
            "tags": t.get("tags", [])
        })

    generate_reports_from_threats()
    return jsonify({"feeds": feeds})


@app.route("/")
def root():
    return redirect(url_for("login"))


@app.route("/homepage")
def homepage():
    ensure_threat_data()
    return render_template("homepage.html")



@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template(
    "dashboard.html",
    username=session.get("username")
    )

@app.route("/ioc-dashboard")
def ioc_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # 🔥 Force data population
    ensure_threat_data()

    return render_template("ioc_dashboard.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        user = users.find_one({"email": email})

        # 1️⃣ Check if user exists
        if not user:
            return render_template(
                "loginpage.html",
                error="❌ Invalid email or password"
            )

        # 2️⃣ Check password
        if not check_password_hash(user["password"], password):
            return render_template(
                "loginpage.html",
                error="❌ Invalid email or password"
            )

        # 3️⃣ Check email verification
        # if not user.get("is_verified", False):
        #     return render_template(
        #         "loginpage.html",
        #         error="⚠️ Please verify your email before logging in."
        #     )

        # 4️⃣ Create session
        session["user_id"] = str(user["_id"])
        session["email"] = user["email"]
        session["username"] = user["username"]

        return redirect(url_for("dashboard"))

    return render_template("loginpage.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))



@app.route("/create-account")
def create_account():
    return render_template("create_account.html")

@app.route("/reports")
def reports():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("reports.html")

@app.route("/api/live-threats")
def live_threats():
    feeds = []

    for t in threats.find().sort("_id", -1).limit(5):
        feeds.append({
            "source": t.get("source", "AlienVault OTX"),
            "title": t.get("title"),
            "severity": "ALERT" if t.get("tlp") in ["RED", "AMBER"] else "SAFE"
        })

    return jsonify(feeds)


@app.route("/api/homepage-stats")
def homepage_stats():
    total_threats = threats.count_documents({})
    alerts = threats.count_documents({"tlp": {"$in": ["RED", "AMBER"]}})

    indicators = 0
    for t in threats.find():
        indicators += len(t.get("tags", []))

    return jsonify({
        "active_feeds": total_threats,
        "new_alerts": alerts,
        "indicators": indicators,
        "new_reports": reports_col.count_documents({})
        
    })

@app.route("/api/generate-report", methods=["POST"])
def generate_report():
    generate_reports_from_threats()
    return jsonify({"status": "success"})


@app.route("/register", methods=["POST"])
def register():

    username = request.form["username"]
    email = request.form["email"]
    password = request.form["password"]
    confirm_password = request.form["confirm_password"]

    # 1️⃣ Password match check
    if password != confirm_password:
        return render_template("create_account.html", error="❌ Passwords do not match")
        # return "❌ Passwords do not match"

    # 2️⃣ Strong password validation
    if not is_strong_password(password):
        return render_template("create_account.html", error="❌ Password must contain uppercase, lowercase, number and special character.")

    # 3️⃣ Check if user already exists
    if users.find_one({"email": email}):
        return render_template("create_account.html", error="❌ User already exists")

    # 4️⃣ Hash password
    hashed_password = generate_password_hash(password)

    # 5️⃣ Save user as NOT verified
    users.insert_one({
        "username": username,
        "email": email,
        "password": hashed_password
    })

    return render_template("loginpage.html", success="✅ Account created successfully! Please login.")

    # return redirect(url_for("login"))

    
 
    # 6️⃣ Generate email verification token
    # token = serializer.dumps(email, salt="email-confirm")

    # verification_link = url_for(
    #     "verify_email",
    #     token=token,
    #     _external=True
    # )

    # # 🔥 Print link in terminal (for testing)
    # print("\n================ EMAIL VERIFICATION LINK ================")
    # print(verification_link)
    # print("=========================================================\n")

    # return "✅ Account created successfully! Please check terminal to verify your email."

# @app.route("/verify/<token>")
# def verify_email(token):
#     try:
#         email = serializer.loads(token, salt="email-confirm", max_age=3600)
#     except Exception:
#         return "❌ Verification link expired or invalid."

#     users.update_one(
#         {"email": email},
#         {"$set": {"is_verified": True}}
#     )

#     return "✅ Email verified successfully! You can now login."

@app.route("/api/iocs")
def api_iocs():
    ip_counter = {}
    domain_counter = {}
    hash_counter = {}

    for doc in iocs_col.find():
        t = doc.get("type", "unknown")
        v = doc.get("value", "unknown")

        if t == "ip":
            ip_counter[v] = ip_counter.get(v, 0) + 1
        elif t == "domain":
            domain_counter[v] = domain_counter.get(v, 0) + 1
        elif t == "hash":
            hash_counter[v] = hash_counter.get(v, 0) + 1

    return jsonify({
        "total_iocs": len(ip_counter) +
               len(domain_counter) +
               len(hash_counter),
        "ips": sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10],
        "domains": sorted(domain_counter.items(), key=lambda x: x[1], reverse=True)[:10],
        "hashes": sorted(hash_counter.items(), key=lambda x: x[1], reverse=True)[:10]
    })

# =========================
# NLP OVERVIEW API
# =========================
@app.route("/api/nlp/overview")
def nlp_overview():
    records = list(nlp_collection.find({}, {
        "_id": 0,
        "severity": 1,
        "category": 1,
        "iocs": 1
    }))

    total_records = len(records)
    high_severity = sum(1 for r in records if r.get("severity") == "High")

    total_iocs = 0
    categories = set()

    for r in records:
        categories.add(r.get("category", "Unknown"))
        iocs = r.get("iocs", {})
        total_iocs += (
            len(iocs.get("ips", [])) +
            len(iocs.get("domains", [])) +
            len(iocs.get("hashes", []))
        )

    return jsonify({
        "total_records": total_records,
        "high_severity": high_severity,
        "total_iocs": total_iocs,
        "categories": len(categories)
    })

# =========================
# NLP IOC DETAILS API
# =========================
@app.route("/api/nlp/iocs")
def nlp_iocs():
    from collections import Counter

    ip_counter = Counter()
    domain_counter = Counter()
    hash_counter = Counter()

    # ✅ 1. FROM NLP COLLECTION
    records = list(nlp_collection.find({}, {"_id": 0, "iocs": 1}))

    for r in records:
        iocs = r.get("iocs", {})
        ip_counter.update(iocs.get("ips", []))
        domain_counter.update(iocs.get("domains", []))
        hash_counter.update(iocs.get("hashes", []))

    # ✅ 2. 🔥 ADD FROM IOC COLLECTION (IMPORTANT FIX)
    for doc in iocs_col.find():
        t = doc.get("type")
        v = doc.get("value")

        if t == "ip":
            ip_counter[v] += 1
        elif t == "domain":
            domain_counter[v] += 1
        elif t == "hash":
            hash_counter[v] += 1

    return jsonify({
        "ips": ip_counter.most_common(10),
        "domains": domain_counter.most_common(10),
        "hashes": hash_counter.most_common(10)
    })

# =========================
# NLP CATEGORY STATS API
# =========================
@app.route("/api/nlp/categories")
def nlp_categories():
    records = list(nlp_collection.find({}, {"_id": 0, "category": 1}))

    counter = Counter(r.get("category", "Unknown") for r in records)

    return jsonify(counter)

@app.route("/api/nlp/reset")
def reset_nlp_data():
    nlp_collection.delete_many({})
    return {"status": "NLP data cleared successfully"}

# =========================
# NLP RECENT INTELLIGENCE
# =========================
@app.route("/api/nlp/recent")
def nlp_recent():
    records = list(
        nlp_collection.find({}, {
            "_id": 0,
            "category": 1,
            "severity": 1,
            "summary": 1,
            "iocs": 1,
            "timestamp": 1
        }).sort("timestamp", -1).limit(20)
    )

    return jsonify(records)

@app.route("/test")
def test():
    return "FLASK IS WORKING"

# =========================
# NLP DASHBOARD ROUTE
# =========================
@app.route("/nlp-dashboard")
def nlp_dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template(
        "nlp_dashboard.html",
        username=session.get("username")
    )


# if __name__ == "__main__":
#     app.run(port=8080, debug=True)

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)