import os
import sys
import json
import requests
from dotenv import load_dotenv
from datetime import datetime
import time

"""
os:       omgevingsvariabelen ophalen
sys:      programma stoppen bij ontbrekende config
json:     resultaten opslaan als JSON logbestand
dotenv:   API-key laden uit .env (veilige data governance)
requests: HTTP-verzoeken naar VirusTotal API
datetime: timestamp toevoegen aan elk logrecord
time:     wachten tussen submit en poll
"""

# Logbestanden
LOG_BESTAND    = "scan_log.json"
THREAT_BESTAND = "threats.json"


def valideer_url(url: str) -> bool:
    """
    Controleert of de ingevoerde URL begint met http:// of https://.
    Retourneert True als geldig, False als ongeldig.
    """
    return url.startswith("http://") or url.startswith("https://")


def vraag_url_aan_gebruiker() -> str:
    """
    Vraagt de gebruiker om een URL in te voeren via de terminal.
    Blijft vragen totdat een geldige URL is ingevoerd.
    """
    while True:
        url = input("\nVoer de te scannen URL in (bijv. https://example.com): ").strip()

        if not url:
            print("[FOUT] Je hebt niets ingevoerd. Probeer opnieuw.")
            continue

        if not valideer_url(url):
            print("[FOUT] Ongeldige URL. Zorg dat de URL begint met http:// of https://")
            continue

        return url


def check_url_virustotal(api_key: str, url_to_scan: str) -> dict | None:
    """
    Stuurt een URL naar de VirusTotal V3 API voor analyse.
    Retourneert de volledige JSON-response of None bij een fout.
    """
    api_url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": url_to_scan}
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    print(f"\n[1/3] Verbinding maken met VirusTotal voor: {url_to_scan}")

    try:
        response = requests.post(api_url, data=payload, headers=headers, timeout=10)
        response.raise_for_status()
        print("[1/3] Verzoek geaccepteerd. Analyse gestart.")
        return response.json()

    except requests.exceptions.ConnectionError:
        print("[FOUT] Geen internetverbinding. Controleer je netwerk en probeer opnieuw.")
    except requests.exceptions.Timeout:
        print("[FOUT] Verbinding time-out. VirusTotal reageert niet binnen 10 seconden.")
    except requests.exceptions.HTTPError as e:
        print(f"[FOUT] HTTP-fout ontvangen: {e}")
    except requests.exceptions.RequestException as e:
        print(f"[FOUT] Onverwachte fout bij het versturen: {e}")

    return None


def get_analysis_report(api_key: str, analysis_id: str) -> dict | None:
    """
    Haalt het analyse-rapport op via het Analysis ID.
    Retourneert de volledige JSON-response of None bij een fout.
    """
    api_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()

    except requests.exceptions.ConnectionError:
        print("[FOUT] Geen internetverbinding bij het ophalen van het rapport.")
    except requests.exceptions.Timeout:
        print("[FOUT] Time-out bij het ophalen van het rapport.")
    except requests.exceptions.HTTPError as e:
        print(f"[FOUT] HTTP-fout bij rapport: {e}")
    except requests.exceptions.RequestException as e:
        print(f"[FOUT] Onverwachte fout bij rapport ophalen: {e}")

    return None


def parse_rapport(rapport: dict, url: str, drempel_gevaarlijk: int, drempel_verdacht_malicious: int, drempel_verdacht_suspicious: int) -> dict | None:
    """
    Extraheert de relevante scores uit de VirusTotal JSON-response.
    Drempelwaarden worden geladen uit .env via de aanroepende code.
    Retourneert een gestructureerd resultaat-dict voor logging én printing.
    """
    try:
        stats = rapport["data"]["attributes"]["stats"]
    except KeyError:
        print("[FOUT] Onverwachte JSON-structuur. Controleer de API-response.")
        return None

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout    = stats.get("timeout", 0)
    totaal     = malicious + suspicious + harmless + undetected + timeout

    # Verdict op basis van configureerbare drempelwaarden uit .env
    if malicious >= drempel_gevaarlijk:
        verdict = "GEVAARLIJK"
    elif malicious >= drempel_verdacht_malicious or suspicious >= drempel_verdacht_suspicious:
        verdict = "VERDACHT"
    else:
        verdict = "VEILIG"

    # Gestructureerd resultaat — geschikt voor logging én printing
    resultaat = {
        "timestamp": datetime.now().isoformat(),
        "url": url,
        "verdict": verdict,
        "stats": {
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   harmless,
            "undetected": undetected,
            "timeout":    timeout,
            "totaal":     totaal,
        }
    }

    # Verdict labels alleen voor terminal output, niet in het logbestand
    verdict_label = {
        "GEVAARLIJK": "GEVAARLIJK - Niet bezoeken",
        "VERDACHT":   "VERDACHT - Wees voorzichtig",
        "VEILIG":     "VEILIG - Geen bedreigingen gevonden",
    }

    print("\n" + "=" * 50)
    print("       VIRUSTOTAL PHISHING ANALYSE RAPPORT")
    print("=" * 50)
    print(f"  URL          : {url}")
    print(f"  Verdict      : {verdict_label[verdict]}")
    print("-" * 50)
    print(f"  Schadelijk   : {malicious:>3}  engines")
    print(f"  Verdacht     : {suspicious:>3}  engines")
    print(f"  Veilig       : {harmless:>3}  engines")
    print(f"  Niet getest  : {undetected:>3}  engines")
    print(f"  Timeout      : {timeout:>3}  engines")
    print(f"  Totaal       : {totaal:>3}  engines")
    print("=" * 50 + "\n")

    return resultaat


def druk_waarschuwing_af(resultaat: dict) -> None:
    """
    Print een duidelijke waarschuwing met advies op basis van het verdict.
    Wordt alleen aangeroepen bij VERDACHT of GEVAARLIJK.
    """
    verdict = resultaat["verdict"]
    stats   = resultaat["stats"]

    if verdict == "GEVAARLIJK":
        print("!" * 50)
        print("  BEVEILIGINGSWAARSCHUWING")
        print("!" * 50)
        print(f"  Deze URL is door {stats['malicious']} engines gemarkeerd als SCHADELIJK.")
        print()
        print("  Aanbevolen acties:")
        print("  - Bezoek deze website NIET")
        print("  - Deel de link NIET met anderen")
        print("  - Meld de URL aan je IT-afdeling of provider")
        print("  - Als je de site al bezocht hebt: scan je apparaat")
        print("!" * 50 + "\n")

    elif verdict == "VERDACHT":
        print("~" * 50)
        print("  WAARSCHUWING - VERDACHTE URL")
        print("~" * 50)
        print(f"  Deze URL is door {stats['malicious']} engine(s) als schadelijk")
        print(f"  en {stats['suspicious']} engine(s) als verdacht aangemerkt.")
        print()
        print("  Aanbevolen acties:")
        print("  - Wees voorzichtig met het bezoeken van deze site")
        print("  - Vul geen persoonlijke gegevens in op deze pagina")
        print("  - Controleer of de URL overeenkomt met de echte domeinnaam")
        print("~" * 50 + "\n")


def sla_resultaat_op(resultaat: dict, bestandsnaam: str = LOG_BESTAND) -> None:
    """
    Voegt het scanresultaat toe aan een JSON logbestand.
    Als het bestand nog niet bestaat, wordt het automatisch aangemaakt.
    Bestaande scans worden nooit overschreven — elk resultaat wordt toegevoegd.
    """
    bestaande_logs = []
    if os.path.exists(bestandsnaam):
        try:
            with open(bestandsnaam, "r", encoding="utf-8") as f:
                bestaande_logs = json.load(f)
        except (json.JSONDecodeError, IOError):
            print(f"[WAARSCHUWING] Kon {bestandsnaam} niet lezen. Nieuw logbestand wordt aangemaakt.")

    bestaande_logs.append(resultaat)

    try:
        with open(bestandsnaam, "w", encoding="utf-8") as f:
            json.dump(bestaande_logs, f, indent=2, ensure_ascii=False)
        print(f"[LOG] Resultaat opgeslagen in: {bestandsnaam}")
    except IOError as e:
        print(f"[FOUT] Kon resultaat niet opslaan: {e}")


def sla_threat_op(resultaat: dict, bestandsnaam: str = THREAT_BESTAND) -> None:
    """
    Slaat alleen VERDACHTE of GEVAARLIJKE URLs op in een apart threats.json bestand.
    Voegt een 'reden' veld toe voor extra context.
    """
    stats = resultaat["stats"]
    threat_record = {
        **resultaat,
        "reden": f"{stats['malicious']} engine(s) schadelijk, {stats['suspicious']} engine(s) verdacht",
    }

    bestaande_threats = []
    if os.path.exists(bestandsnaam):
        try:
            with open(bestandsnaam, "r", encoding="utf-8") as f:
                bestaande_threats = json.load(f)
        except (json.JSONDecodeError, IOError):
            print(f"[WAARSCHUWING] Kon {bestandsnaam} niet lezen. Nieuw threatbestand wordt aangemaakt.")

    bestaande_threats.append(threat_record)

    try:
        with open(bestandsnaam, "w", encoding="utf-8") as f:
            json.dump(bestaande_threats, f, indent=2, ensure_ascii=False)
        print(f"[THREAT LOG] Bedreiging opgeslagen in: {bestandsnaam}")
    except IOError as e:
        print(f"[FOUT] Kon threat niet opslaan: {e}")


if __name__ == "__main__":
    # --- Configuratie laden ---
    load_dotenv()
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        print("[FOUT] Geen API-key gevonden. Controleer je .env bestand.")
        sys.exit(1)

    # --- Drempelwaarden laden (met standaardwaarden als fallback) ---
    drempel_gevaarlijk          = int(os.getenv("DREMPEL_GEVAARLIJK", 3))
    drempel_verdacht_malicious  = int(os.getenv("DREMPEL_VERDACHT_MALICIOUS", 1))
    drempel_verdacht_suspicious = int(os.getenv("DREMPEL_VERDACHT_SUSPICIOUS", 3))

    # --- Stap 1: Gebruiker voert URL in ---
    test_url = vraag_url_aan_gebruiker()

    # --- Stap 2: Submit ---
    resultaat = check_url_virustotal(api_key, test_url)
    if not resultaat:
        sys.exit(1)

    analysis_id = resultaat["data"]["id"]
    print(f"[2/3] Analysis ID ontvangen: {analysis_id}")

    # --- Stap 3: Wachten ---
    wacht_seconden = 15
    print(f"[2/3] Wachten {wacht_seconden}s op voltooiing van de analyse...")
    time.sleep(wacht_seconden)

    # --- Stap 4: Rapport ophalen, parsen en opslaan ---
    print("[3/3] Rapport ophalen...")
    rapport = get_analysis_report(api_key, analysis_id)
    if rapport:
        scan_resultaat = parse_rapport(rapport, test_url, drempel_gevaarlijk, drempel_verdacht_malicious, drempel_verdacht_suspicious)
        if scan_resultaat:
            sla_resultaat_op(scan_resultaat)

            if scan_resultaat["verdict"] in ("VERDACHT", "GEVAARLIJK"):
                druk_waarschuwing_af(scan_resultaat)
                sla_threat_op(scan_resultaat)
