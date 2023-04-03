
import pyshark
import matplotlib.pyplot as plt
import numpy as np

# voir description des scénarios rapport

f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"

cap_login = pyshark.FileCapture(f_login)
cap_call = pyshark.FileCapture(f_call)
cap_screen = pyshark.FileCapture(f_screen)
cap_msg = pyshark.FileCapture(f_msg)

x = ['Authentification', 'Appel audio-vidéo', 'Partage d\'écran' , 'Messagerie']
val = [[0,0],[0,0],[0,0],[0,0]] # UDP-TCP
cat = ["UDP", "TCP"]


p = cap_login[0]
print(p.transport_layer)

"""
i = 0
nt = 0
nt_save = []
for cap in [cap_login,cap_call,cap_screen,cap_msg]:
    for pkt in cap:
        if ("UDP" == pkt.transport_layer):
            val[i][0] += 1
        elif ("TCP" == pkt.transport_layer):
            val[i][1] += 1
        else : 
            #print("No transport protocol\n", pkt)
            nt+=1
            nt_save.append(pkt)
    i+=1
"""

val = np.array([[56,523],[6352,1274],[4463,989],[7,148]])

pourcentages = 100 * val/ np.sum(val, axis=1, keepdims=True)

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