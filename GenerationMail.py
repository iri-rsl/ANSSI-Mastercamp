import smtplib
from email.mime.text import MIMEText
import pandas as pd

# Paramètres de configuration
FROM_EMAIL = "from.aiciDS5@gmail.com"
APP_PASSWORD = "pmfakazcgvxwpkrq " # Aici@2004
TO_EMAIL = "to.aiciDS5@gmail.com"

def send_email(to_email, subject, body):
    msg = MIMEText(body)
    msg['From'] = FROM_EMAIL
    msg['To'] = to_email
    msg['Subject'] = subject

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(FROM_EMAIL, APP_PASSWORD)
        server.sendmail(FROM_EMAIL, to_email, msg.as_string())
        server.quit()
        print(f"Email envoyé à {to_email}")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email : {e}")


def check_critical_vulnerabilities(csv_path):
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["cvss_score", "epss_score"])
    df["cvss_score"] = df["cvss_score"].astype(float)
    df["epss_score"] = df["epss_score"].astype(float)

    # Seuils d’alerte
    critical = df[(df["cvss_score"] >= 9) | (df["epss_score"] >= 0.9)]

    for _, row in critical.iterrows():
        subject = f"ALERTE CVE CRITIQUE : {row['cve_id']}"
        body = (
            f"Titre : {row['title']}\n"
            f"Date : {row['date']}\n"
            f"CVE : {row['cve_id']}\n"
            f"Score CVSS : {row['cvss_score']}\n"
            f"Score EPSS : {row['epss_score']}\n"
            f"Produit : {row['product']}\n"
            f"Éditeur : {row['vendor']}\n"
            f"\nLien : {row['link']}\n"
            f"\nDescription :\n{row['description']}\n"
        )
        send_email(TO_EMAIL, subject, body)

check_critical_vulnerabilities("data/final_cve_data.csv")