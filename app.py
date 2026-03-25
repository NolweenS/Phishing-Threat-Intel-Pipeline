from flask import Flask, render_template, request, jsonify
from main import check_url_virustotal, get_analysis_report, parse_rapport, sla_resultaat_op, sla_threat_op, valideer_url
from dotenv import load_dotenv
import os
import json
import time

load_dotenv()
app = Flask(__name__)

api_key = os.getenv("VT_API_KEY")
drempel_gevaarlijk          = int(os.getenv("DREMPEL_GEVAARLIJK", 3))
drempel_verdacht_malicious  = int(os.getenv("DREMPEL_VERDACHT_MALICIOUS", 1))
drempel_verdacht_suspicious = int(os.getenv("DREMPEL_VERDACHT_SUSPICIOUS", 3))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url or not valideer_url(url):
        return jsonify({"error": "Ongeldige URL. Zorg dat de URL begint met http:// of https://"}), 400

    resultaat = check_url_virustotal(api_key, url)
    if not resultaat:
        return jsonify({"error": "Kon geen verbinding maken met VirusTotal."}), 500

    analysis_id = resultaat["data"]["id"]
    time.sleep(15)

    rapport = get_analysis_report(api_key, analysis_id)
    if not rapport:
        return jsonify({"error": "Kon het analyserapport niet ophalen."}), 500

    scan_resultaat = parse_rapport(rapport, url, drempel_gevaarlijk, drempel_verdacht_malicious, drempel_verdacht_suspicious)
    if not scan_resultaat:
        return jsonify({"error": "Fout bij het verwerken van het rapport."}), 500

    sla_resultaat_op(scan_resultaat)
    if scan_resultaat["verdict"] in ("VERDACHT", "GEVAARLIJK"):
        sla_threat_op(scan_resultaat)

    return jsonify(scan_resultaat)


@app.route("/geschiedenis")
def geschiedenis():
    if not os.path.exists("scan_log.json"):
        return jsonify([])
    try:
        with open("scan_log.json", "r", encoding="utf-8") as f:
            logs = json.load(f)
        return jsonify(list(reversed(logs)))
    except (json.JSONDecodeError, IOError):
        return jsonify([])


if __name__ == "__main__":
    app.run(debug=True, port=8080)
