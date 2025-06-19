# Projet de Récupération et Traitement des Alertes ANSSI

Ce projet permet de :
- Récupérer les alertes de sécurité publiées par l’ANSSI.
- Générer un fichier CSV contenant ces données.
- Analyser ces données via un notebook Jupyter.
- Envoyer des mails avec les informations récupérées.

---

## À vérifier au préalable

Avant de commencer, assurez-vous d'être l'un des deux cas :

- Utiliser l'interpréteur python de Anaconda
- Installer toutes les librairies nécessaires : feedparser, pandas, numpy, matplotlib, seaborn, os, requests, re, time, json, smtplib, email.mime.text etc.

## Génération du fichier CSV

1. Ouvrir le fichier GenerationCSV.py.
2. Lancer simplement le script.
3. Un fichier .csv devrait apparaître automatiquement dans le même dossier que le script.

## Analyse dans le Notebook
1. Dans le fichier .ipynb fourni (notebook Jupyter) :
2. Vérifiez que la ligne suivante contient le bon nom du fichier CSV généré : df = pd.read_csv("nom_du_fichier.csv")
3. Adaptez "nom_du_fichier.csv" selon le nom réel du fichier généré précédemment.

## Génération et Envoi des Mails
1. Ouvrir et exécuter le fichier GenerationMail.py.
2. Les mails seront automatiquement envoyés.

## Vérification de l’envoi
Vous pouvez vérifier les envois dans la boîte mail dédiée :
- Adresse mail : to.aiciDS5@gmail.com
- Mot de passe : Aici@2004

