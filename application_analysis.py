import pyshark
import matplotlib.pyplot as plt
import numpy as np


paquet_totaux = False

if paquet_totaux : 
    f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
    f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
    f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
    f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"

    cap_login = pyshark.FileCapture(f_login)
    cap_call = pyshark.FileCapture(f_call)
    cap_screen = pyshark.FileCapture(f_screen)
    cap_msg = pyshark.FileCapture(f_msg)

    data = []

    caps = [cap_login, cap_call , cap_screen, cap_msg]
    labels = ['Authentification', 'Appel audio-vidéo', 'Partage d\'écran' , 'Messagerie']

    # Compter le nombre de paquets par seconde
    for cap in caps:
        packets_per_second = {}
        start_time = None
        for packet in cap:
            if start_time is None:
                start_time = float(packet.sniff_time.timestamp())
            timestamp = float(packet.sniff_time.timestamp())
            seconds = int(timestamp - start_time)
            if seconds not in packets_per_second:
                packets_per_second[seconds] = 0
            packets_per_second[seconds] += 1
        data.append(packets_per_second)

    # Créer un graphique du nombre de paquets par seconde
    colors = colors = ["tab:blue","tab:red", "tab:green", "tab:orange"]

    fig, axs = plt.subplots(4,1)
    fig.suptitle('Nombre de paquets par seconde')
    for i in range(len(caps)):     
        axs[i].plot(list(data[i].keys()), list(data[i].values()), color = colors[i], label = labels[i], alpha = 0.9)
        #axs[i].grid(True)
        axs[i].legend(loc='upper right')
        axs[i].set_ylim(0,550)


    fig.supxlabel('Temps [s]')
    fig.supylabel('Nombre de paquets')
    fig.tight_layout()
    plt.show()

count_udp = False

if count_udp : 
    f_audio = "packet_traces/M_Linux/FileCapture_Any_1min_audio.pcapng"
    f_video = "packet_traces/M_Linux/FileCapture_Any_1min_audiovideo.pcapng"
    f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"

    cap_audio = pyshark.FileCapture(f_audio, display_filter='udp')
    cap_video = pyshark.FileCapture(f_video, display_filter='udp')
    cap_screen = pyshark.FileCapture(f_screen, display_filter='udp')

    count_audio = 0 # volume échangés [bytes]
    count_video = 0 # volume échangés [bytes]
    count_screen = 0 # volume échangés [bytes]

    for pkt in cap_audio:
        if('<DATA Layer>' in str(pkt.layers)) : 
            count_audio += int(pkt.DATA.data_len)
        elif ('WG Layer' in str(pkt.layers)) : 
            count_audio += int(pkt.length)
        else : 
            pass

    for pkt in cap_video : 
        if('<DATA Layer>' in str(pkt.layers)) : 
            count_video += int(pkt.DATA.data_len)
        elif ('WG Layer' in str(pkt.layers)) : 
            count_video += int(pkt.length)
        else : 
            pass

    start_share = 47 #s
    end_share = 67 #s
    start_time = None
                
    for pkt in cap_screen:
        if start_time is None:
            start_time = float(pkt.sniff_time.timestamp())
        timestamp = float(pkt.sniff_time.timestamp())
        seconds = int(timestamp - start_time)
        if (seconds < start_share) :
            continue
        elif (seconds > end_share):
            break
        else :
            if('<DATA Layer>' in str(pkt.layers)) : 
                count_screen += int(pkt.DATA.data_len)
            elif ('WG Layer' in str(pkt.layers)) : 
                count_screen += int(pkt.length)
            else : 
                pass

    count_screen = int(count_screen * (60/(end_share-start_share)))

    print("# Packets UDP - 1min audio = ", count_audio, " [bytes]")
    print("# Packets UDP - 1min audio+video = ", count_video, " [bytes]")
    print("# Packets UDP - 1min partage écran = ", count_screen, " [bytes]")


