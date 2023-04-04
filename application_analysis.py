import pyshark
import matplotlib.pyplot as plt
import numpy as np



f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"

f_audio = "packet_traces/M_Linux/FileCapture_Any_1min_audio.pcapng"
f_video = "packet_traces/M_Linux/FileCapture_Any_1min_audiovideo.pcapng"

cap_call = pyshark.FileCapture(f_call)
cap_screen = pyshark.FileCapture(f_screen)
cap_msg = pyshark.FileCapture(f_msg)

cap_audio = pyshark.FileCapture(f_audio)
#cap_video = pyshark.FileCapture(f_video)


# Initialiser les variables
packets_per_second = {}
start_time = None

# Compter le nombre de paquets par seconde
for packet in cap_audio:
    if start_time is None:
        start_time = float(packet.sniff_time.timestamp())
    timestamp = float(packet.sniff_time.timestamp())
    seconds = int(timestamp - start_time)
    if seconds not in packets_per_second:
        packets_per_second[seconds] = 0
    packets_per_second[seconds] += 1

# Créer un graphique du nombre de paquets par seconde

plt.plot(list(packets_per_second.keys()), list(packets_per_second.values()))
plt.xlabel('Temps [s]')
plt.ylabel('Nombre de paquets')
plt.show()
