import pyshark
import matplotlib.pyplot as plt
import numpy as np

# Voir RAPPORT pour la description des scénarios

verification_DNSSEC = False # mettre à True pour effectuer la vérification

if verification_DNSSEC:

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

# Note : Finalement, les données pour la version de TLS sont directement ramenées depuis Wireshark et non via pyshark
# Il n'y a pas de moyen simple d'accéder à la version (!= pkt.tls.record.version), moyen via only_summaries 
# mais alors impossible d'itérer sur les packets.

if False : 
    f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
    f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
    f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
    f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"


    cap_login = pyshark.FileCapture(input_file = f_login, display_filter='tls')
    cap_call = pyshark.FileCapture(f_call, display_filter='tls')
    cap_screen = pyshark.FileCapture(f_screen, display_filter='tls')
    cap_msg = pyshark.FileCapture(f_msg, display_filter='tls')

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



plot_TLS_version_repartition = False # mettre à True pour afficher le graphe

if plot_TLS_version_repartition : 

    x = ['Authentification', 'Appel audio-vidéo', 'Partage d\'écran' , 'Messagerie']
    cat = ["TLSv1.3","TLSv1.2"]
    val = [[79,140],[580,32],[423,37],[11,48]] # valeurs depuis Wireshark
    v = np.array(val)

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
    plt.title("Versions TLS")
    plt.ylabel("Pourcentage [%]")
    plt.xlabel("Fonctionnalités")
    plt.show()


### Analyse des certificats




# Durée de vie des certificats ?

ttl_certificates = False


if ttl_certificates : 

    f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
    f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
    f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
    f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"

    cap_login = pyshark.FileCapture(f_login, display_filter='tls.handshake.certificate', use_json=0)
    cap_call = pyshark.FileCapture(f_call, display_filter='tls.handshake.certificate', use_json=0)
    cap_screen = pyshark.FileCapture(f_screen, display_filter='tls.handshake.certificate', use_json=0)
    cap_msg = pyshark.FileCapture(f_msg, display_filter='tls.handshake.certificate', use_json=0)

    data = {} 

    for cap in [cap_login,cap_call,cap_screen,cap_msg]:
        for pkt in cap :
            try : 
                ttl = pkt.ip.ttl
                if(ttl not in data.keys()):
                    data[ttl] = 1
                else:
                    data[ttl] += 1 
            except:
                print("no ip layer")
                continue

    print(data)


# Algo de chiffrement 
# Ligne pour récupérer : pkt.tls.record.handshake.certificates.certificate_tree[i].algorithmIdentifier_element.id

algochiffrement = False

if algochiffrement : 

    f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
    f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
    f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
    f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"

    cap_login = pyshark.FileCapture(f_login, display_filter='tls.handshake.certificate', use_json=1)
    cap_call = pyshark.FileCapture(f_call, display_filter='tls.handshake.certificate', use_json=1)
    cap_screen = pyshark.FileCapture(f_screen, display_filter='tls.handshake.certificate', use_json=1)
    cap_msg = pyshark.FileCapture(f_msg, display_filter='tls.handshake.certificate', use_json=1)


    data = {} 

    for cap in [cap_login,cap_call,cap_screen,cap_msg]:
        for pkt in cap :
            algos = pkt.tls.record.handshake.certificates.certificate_tree
            try : 
                for algo in algos:
                    a = algo.algorithmIdentifier_element.id
                    if(a not in data.keys()):
                        data[a] = 1
                    else:
                        data[a] += 1 
            except:
                print("error")
                continue

    print(data)

    labels = list(data.keys())
    values = list(data.values())

    explode = (0, 0.1)  # only "explode" the 2nd slice

    fig, ax = plt.subplots()
    ax.pie(values, explode=explode, labels=labels, autopct='%1.1f%%',
            shadow=True, startangle=90, colors = ["tab:blue","tab:red"], wedgeprops={"alpha": 0.9} )
    plt.title("Algorithmes de chiffrement utilisés")
    plt.show()