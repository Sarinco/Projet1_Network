# LINFO1341 - Projet 1 : Analyse de traces d'un logiciel de vidéo-conférence (Groupe Zoom7)

Ce répertoire GitHub contient l'ensemble du code Python utilisant `PyShark` permettant l'analyse de nos traces capturées avec `WireShark`.

## Captures

- Les fichiers de captures utilisés se trouvent dans le répertoire 'packet_traces'.
- La description des scénarios se trouvent dans 'infos_capture.md'.

## Graphes

- Les graphes produits se trouvent dans le répertoire 'graphs'.

## Code

Pour exécuter le programme `dns_analysis.py`, lancer la commande suivante dans le terminal : 
```
python dns_analysis.py option
```
- avec *option* : 
    - *graph* pour générer les graphes
    - *domain* pour afficher sur la sortie standard les noms de domaines résolus
    - *authoritative* pour afficher sur la sortie standard les serveurs autoritatifs rencontrés
    - *type* pour afficher sur la sortie standard si les requêtes DNS sont récursives ou non
    - *additional* pour afficher sur la sortie standard les différents champs possibles pour chaque paquet DNS

Pour exécuter les programmes `network_analysis.py` ou `transport_analysis.py`, lancer les commandes suivantes dans le terminal sans argument particulier : 
```
python network_analysis.py
python transport_analysis.py
```

Pour exécuter le programme `security_analysis.py`, lancer la commande suivante dans le terminal
```
python security_analysis.py option
```
- avec *option* : 
    - *checkDNSSEC* pour vérifier si l'extension DNSSEC est utilisée ou non
    - *TLS* pour afficher le graphe représentant la répartition des versions de TLS
    - *certTTL* pour afficher sur la sortie standard les Time-To-Live des paquets contenant les certificats
    - *algo* pour afficher le graphe représentant la répartition des algorithmes de chiffrement des certificats

Pour exécuter le programme `application_analysis.py`, lancer la commande suivante dans le terminal
```
python application_analysis.py option
```
- avec *option* : 
    - *plot_pkt* pour afficher le graphe représentant le nombre de paquet échangés en fonction du temps
    - *volume* pour calculer les volumes UDP de données échangées pour 1 minute d'appel audio, d'appel audio-vidéo, de partage d'écran


