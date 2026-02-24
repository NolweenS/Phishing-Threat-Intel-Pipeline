import os
import sys
import requests
from dotenv import load_dotenv
import  time

"""
os: to get environment variables
sys: to exit the program if required environment variables are not set
dotenv: to load environment variables from a .env file
This allows us to keep sensitive information like API keys out of our codebase
requests: to make requests to external APIs such as VirusTotal
"""


def check_url_virustotal(api_key, url_to_scan):
    # Stuurt een URL naar VirusTotal om te scannen en retourneert de scan ID
    # Het eindpoint voor het scannen van een URL op VirusTotal
    api_url = 'https://www.virustotal.com/api/v3/urls'

    # De URL door sturen als een parameter in de POST request
    playload = {'url': url_to_scan}

    # De headers bevatten de API key voor authenticatie
    headers = {"accept": "application/json",
               "x-apikey": api_key
               }
    print(f"Verbinding maken met VirusTotal om de URL te scannen: {url_to_scan}...")

    # Maken van een POST-verzoek om de scan te starten
    response = requests.post(api_url, data=playload, headers=headers)

    if response.status_code == 200:
        # De scan is succesvol gestart, we kunnen de scan ID uit de response halen
        print("Verzoek succesvol ontvangen. URL is in behandeling voor scan.")
        return response.json()
    else:
        # Er is een fout opgetreden bij het verzenden van het scanverzoek, we loggen de fout en retourneren None
        print(f"Fout bij het verzenden van de scanverzoek: {response.status_code} - {response.text}")
        return None

def get_analysis_report(api_key, analysis_id):
    # Stuurt een GET-verzoek naar VirusTotal om het scanrapport op te halen
    api_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'

    headers = {"accept": "application/json",
               "x-apikey": api_key}
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None


if __name__ == "__main__":
    # Valideer de config en laad de API key uit de omgeving
    load_dotenv()
    key = os.getenv("VT_API_KEY")

    if not key:
        print("FOUT: geen API-key gevonden")
        sys.exit(1)

    # Voorbeeld  van een URL om te testen
    test_url = "https://www.google.com"
    resultaat = check_url_virustotal(key, test_url)

    #
    if resultaat:
        # De scan is gestart, we kunnen de scan ID gebruiken om het rapport later op te vragen
        current_id = resultaat['data']['id']
        print(f"Scan gestart. Analysis ID: {current_id}")

        # Wacht een paar seconden voordat we het rapport opvragen, zodat de scan tijd heeft om te voltooien
        print("Even wachten op de analyse om te voltooien...")
        #wacht 15 seconden voordat het rapport wordt opgevraagd
        time.sleep(15)

        # Vraag het scan
        rapport = get_analysis_report(key, current_id)
        if rapport:
            print("Scanrapport ontvangen:")
            print(rapport)


