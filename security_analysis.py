import pyshark
import matplotlib.pyplot as plt
import numpy as np

# voir description des scénarios rapport

if False:

    f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
    f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
    f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
    f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"

    cap_login = pyshark.FileCapture(f_login, display_filter='dns', use_json=True)
    cap_call = pyshark.FileCapture(f_call, display_filter='dns', use_json=True)
    cap_screen = pyshark.FileCapture(f_screen, display_filter='dns', use_json=True)
    cap_msg = pyshark.FileCapture(f_msg, display_filter='dns', use_json=True)

    ### VERIFICATION DNS SECURISE (extension DNSSEC)

    def useDNSSEC():
        count = 0
        for cap in [cap_login,cap_call,cap_screen,cap_msg]:
            for pkt in cap:
                if(pkt.dns.add_rr != '0'):
                    count +=1 
                    print("Extension détectée ! ")
                    print(pkt)

        print("Utilisation de l'extension DNSSEC : " , count!=0)
        return count!=0


### Statistiques Version TLS


############################# A CORRIGER -> difficulté de lire la version comme sur Wireshark


f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"


cap_login = pyshark.FileCapture(input_file = f_login, display_filter='tls.version != 0x0301')
cap_call = pyshark.FileCapture(f_call, display_filter='tls', only_summaries = True)
cap_screen = pyshark.FileCapture(f_screen, display_filter='tls', only_summaries = True)
cap_msg = pyshark.FileCapture(f_msg, display_filter='tls', only_summaries = True)

for pkt in cap_login:
    print(pkt)


####################### EN COURS DE MODIF : pyshark pue la merde on sait pas itérer avec les récaps

"""
x = ['Authentification', 'Appel audio-vidéo', 'Partage d\'écran' , 'Messagerie']
val = []


for cap in [cap_login,cap_call,cap_screen,cap_msg]:
    data = {}
    for pkt in cap:
        tls_version = pkt.protocol
        if("TLS" not in str(tls_version)):
            continue #skip ce pkt
        if(tls_version not in data.keys()):
            data[tls_version] = 1
        else :
            data[tls_version] +=1 
    val.append(data)

print(val)

v = []
for i in range(4):
    v.append([])
    dic = val[i]
    keys = list(dic.keys())
    for j in range(len(keys)):
        v[i].append(dic[keys[j]])

v = np.array(v)
cat = list(val[0].keys())

pourcentages = 100 * v/ np.sum(v, axis=1, keepdims=True)

fig, ax = plt.subplots()

largeur_barre = 0.5
colors = ["tab:blue","tab:red"]
#colors = ["dodgerblue","crimson"]

for i, cat in enumerate(cat):
    ax.bar(x, pourcentages[:,i], width=largeur_barre, label=cat,color = colors[i],alpha = 0.9, bottom=np.sum(pourcentages[:,:i], axis=1))
    #ax.bar(x, pourcentages[:,i], width=largeur_barre, label=cat, bottom=np.sum(pourcentages[:,:i], axis=1))

ax.set_xticks(x)
ax.set_xticklabels(x)
#plt.xticks(rotation=45, ha='right')
ax.legend()
plt.title("Protocoles de transport")
plt.ylabel("Pourcentage [%]")
plt.xlabel("Fonctionnalités")

plt.show()


cap_login.close()
cap_call.close()
cap_screen.close()
cap_msg.close()

"""