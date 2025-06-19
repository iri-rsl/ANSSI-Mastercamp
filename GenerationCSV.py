import feedparser
import requests
import re
import time
import pandas as pd
from tqdm import tqdm

def extract_rss_entries():
    urls = [
        "https://www.cert.ssi.gouv.fr/avis/feed",
        "https://www.cert.ssi.gouv.fr/alerte/feed"
    ]
    entries = []
    for url in urls:
        feed = feedparser.parse(url)
        for entry in feed.entries:
            entries.append({
                'id': entry.link.split("/")[-2],
                'title': entry.title,
                'link': entry.link,
                'type': "Alerte" if "alerte" in url else "Avis",
                'date': entry.published
            })
    return entries

def extract_cves_from_json(entry_link):
    try:
        json_url = entry_link + "/json/"
        response = requests.get(json_url)
        data = response.json() # fichier JSON complet de l'entrée RSS

        # Extraction des références CVE dans la clé cves du dict data
        cve_refs = data.get("cves", [])

        # Extraction des CVE avec une regex
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list = list(set(re.findall(cve_pattern, str(data))))

        # Retourne la liste de CVE référence pour l'entrée RSS entrée en argument + le JSON complet de l'entrée RSS
        return cve_refs, data
    except:
        return [], {}
    
def enrich_cve(cve_id):
    mitre = {}
    epss_score = None

    # API CVE de Mitre
    try:
        mitre_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        r = requests.get(mitre_url)
        mitre_data = r.json()

        # Extraire la description de la CVE
        description = mitre_data["containers"]["cna"]["descriptions"][0]["value"]
        mitre['description'] = description

        # Extraire le score et sévérité CVSS
        cvss_score = None
        base_severity = ""
        metrics = mitre_data["containers"]["cna"].get("metrics", [])
        if metrics:
            cvss_info = metrics[0]
            for key in cvss_info.keys():
                if key.startswith('cvss'):
                    cvss = cvss_info.get(key, {})                
                    if cvss:
                        cvss_score = cvss.get("baseScore")
                        base_severity = cvss.get("baseSeverity")
                        break

        mitre['cvss_score'] = cvss_score
        mitre['base_severity'] = base_severity

        # Extraire le CWE (type de vulnérabilité)
        cwe = "Non disponible"
        cwe_desc = "Non disponible"
        problemtype = mitre_data["containers"]["cna"].get("problemTypes", {})
        if problemtype and "descriptions" in problemtype[0]:
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")

        mitre['cwe'] = cwe
        mitre['cwe_desc'] = cwe_desc

        # Extraire les produits affectés
        affected = mitre_data["containers"]["cna"]["affected"]
        for product in affected:
            vendor = product["vendor"]
            product_name = product["product"]
            versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
            mitre['vendor'] = vendor
            mitre['product'] = product_name
            mitre['versions'] = versions

    except Exception as e:
        print(f"Erreur lors de l'enrichissement de {cve_id} : {e}")
        pass

    # API EPSS de First
    try:
        epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        r = requests.get(epss_url)
        epss_json = r.json()

        # Extraire la liste data du JSON (contenant le score EPSS)
        epss_data = epss_json.get("data", [])

        # Si la liste n'est pas vide, extraire le score EPSS
        if epss_data:
            epss_score = epss_data[0]["epss"]

        # Sinon, signaler le manque de score EPSS
        else:
            print(f"Aucun score EPSS trouvé pour {cve_id}")
    except Exception as e:
        print(f"Erreur lors de l'enrichissement de {cve_id} : {e}")
        epss_score = None

    return mitre, epss_score


def process_entries(entries, limit=None):
    all_rows = []

    # Limiter la liste d'entrés RSS si l'argument limit n'est pas None
    entries = entries[:limit] if limit else entries

    for entry in tqdm(entries):
        time.sleep(2)  # Pause de 2 secondes pour éviter de surcharger les serveurs
        # Récupérer la liste de CVE référence pour chaque entrée RSS
        cve_refs, full_json = extract_cves_from_json(entry['link'])

        # Si la liste de CVE est vide, on passe à l'entrée suivante
        if not cve_refs:
            print(f"Pas de CVE référence pour l'entrée RSS {entry['id']}, {entry['link']}")
            continue

        nb_cve = len(cve_refs)
        print(f"{nb_cve} vulnérabilités dans le bulletin {entry['id']}")

        # Dans le cas ou la liste de CVE existe, nous ajoutons ses informations dans un DataFrame
        cve_counter = 0
        for cve in cve_refs:
            cve_counter += 1
            print(f"Traitement CVE {cve['name']} : {cve_counter}/{nb_cve}")

            # Extraction du nom de la CVE (identifiant unique)
            cve_id = cve['name']

            # Extraction des informations sur l'entrée RSS
            entry_id = entry['id']
            entry_title = entry['title']
            entry_type = entry['type']
            entry_date = entry['date']
            entry_link = entry['link']

            # Extraction des données de l'API Mitre et du score EPSS à partir de l'identifiant de la CVE
            mitre, epss_score = enrich_cve(cve_id)

            all_rows.append({
                'id': entry_id,
                'title': entry_title,
                'type': entry_type,
                'date': entry_date,
                'cve_id': cve_id,
                'cvss_score': mitre.get('cvss_score'),
                'base_severity': mitre.get('base_severity'),
                'type_cwe': mitre.get('cwe'),
                'cwe_desc': mitre.get('cwe_desc'),
                'epss_score': epss_score,
                'link': entry_link,
                'description': mitre.get('description'),
                'vendor': mitre.get('vendor'),
                'product': mitre.get('product'),
                'versions': mitre.get('versions'),
            })

    df = pd.DataFrame(all_rows)
    return df


def main():
    entries = extract_rss_entries()
    df = process_entries(entries)
    df.to_csv("data2/final_cve_data.csv", index=False)
    print("✅ Données exportées dans final_cve_data.csv")

if __name__ == "__main__":
    main()