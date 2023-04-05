# Détails des captures

Ce fichier détaille le déroulé exact de chaque scénario utilisé dans le rapport.

Note : Utilisateur 1 := U1 (M) , Utilisateur 2 := U2 (A)

Les différents fichiers de capture mentionnés dans le rapport sont les suivants : 

1)  **Authentification** : 'packet_traces/M_Linux/FileCapture_Any_1min_audio.pcapng'


- *0s* : U1 lance la capture Wireshark
- *1s* : U1 lance l'application Zoom, U1 introduit son identifiant et son mot de passe
- *30s* : Connexion établie pour U1

2) **Appel audio-vidéo** : 'packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng'

- *0s* : U1 lance la capture Wireshark
- *3s* : U1 démarre la réunion 
- *17s* : U1 invite U2 à rejoindre la réunion
- *33s* : U2 rejoint la réunion, U1 et U2 ont le micro et la caméra coupés
- *37s* : U1 active son micro
- *43s* : U1 désactive son micro
- *46s* : U2 active son micro
- *52s* : U2 désactive son micro
- *56s* : U1 active sa caméra
- *61s* : U1 désactive sa caméra
- *63s* : U2 active sa caméra
- *68s* : U2 désactive sa caméra
- *72s* : U1 et U2 activent leur micro et leur caméra
- *83s* : U1 met fin à la réunion

3) **Partage d'écran** : 'packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng'

- *0s* : U1 lance la capture Wireshark
- *6s* : U1 démarre la réunion 
- *17s* : U1 invite U2 à rejoindre la réunion
- *36s* : U2 rejoint la réunion, U1 et U2 ont le micro et la caméra coupés
- *47s* : U1 partage son écran
- *67s* : U1 coupe son partage d'écran
- *78s* : U1 met fin à la réunion

4) **Messagerie** : 'packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng'

- *0s* : U1 lance la capture Wireshark
- *12s* : U1 envoie msg1 à U2
- *22s* : U1 reçoit msg2 de U2
- *30s* : U1 envoie msg3 à U2
- *46s* : U1 reçoit msg4 de U2
- *53s* : U1 envoie msg5 à U2
- *60s* : U1 reçoit msg6 de U2


5) **1min Audio** : 'packet_traces/M_Linux/FileCapture_Any_1min_audio.pcapng'

- U1 et U2 sont en réunion et ont leur micro activé
- *0s* : U1 lance la capture Wireshark
- *60s* : U1 arrête la capture Wireshark

6) **1min Audio-Vidéo** : 'packet_traces/M_Linux/FileCapture_Any_1min_audiovideo.pcapng'

- U1 et U2 sont en réunion et ont leur micro et caméra activés
- *0s* : U1 lance la capture Wireshark
- *60s* : U1 arrête la capture Wireshark