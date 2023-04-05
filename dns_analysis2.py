import pyshark
import matplotlib.pyplot as plt
import numpy as np

dns_barh = False

if dns_barh : 

    f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
    f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
    f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
    f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"

    cap_login = pyshark.FileCapture(f_login, display_filter='dns')
    cap_call = pyshark.FileCapture(f_call, display_filter='dns')
    cap_screen = pyshark.FileCapture(f_screen, display_filter='dns')
    cap_msg = pyshark.FileCapture(f_msg, display_filter='dns')

    data = []

    caps = [cap_login, cap_call , cap_screen, cap_msg]
    labels = ['Authentification', 'Appel audio-vidéo', 'Partage d\'écran' , 'Messagerie']
    val = []

    for cap in caps:
        count = 0
        for pkt in cap:
            count +=1
        val.append(count)


    colors = ["tab:blue","tab:red", "tab:green", "tab:orange"]
    pos = [0,0.5,1,1.5]
    fig, ax = plt.subplots()
    ax.barh(pos, val, align='center', color = colors, alpha=0.9, height=0.3)
    ax.set_yticks(pos, labels=labels)
    ax.invert_yaxis()
    ax.set_title("Nombre de paquet DNS par scénarios")
    plt.tight_layout()
    plt.show()
