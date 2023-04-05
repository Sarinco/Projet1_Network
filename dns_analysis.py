import pyshark as ps
import numpy as np
import matplotlib.pyplot as plt
import sys
from os import listdir
from os.path import isfile

def computeexperimentTime(tracePath):
    """function that computes the time between the first and last packet of the trace
    Args:
        tracePath (pcapng file): a packet trace
    """
    capture = ps.FileCapture(tracePath, include_raw=True, use_json=True)
    firstPacketTime = None
    lastPacketTime = None
    for pkt in capture:
        if firstPacketTime == None:
            firstPacketTime = pkt.sniff_time
        lastPacketTime = pkt.sniff_time
        
    capture.close()
    return lastPacketTime - firstPacketTime

def CountDNSPackets(tracePath):
    capture = ps.FileCapture(tracePath, display_filter='dns')
    print("capture de :" + tracePath)
    domainCount = 0
    for pkt in capture:
        domainCount += 1
    capture.close()
    return domainCount

def to_seconds(dt_time):
    return 60*dt_time.minute + dt_time.seconds

def graphmaker(traceList):
    """Function that makes a bar graph of the number of packets per dns protocol
    Args:
        traceList (pcapng files): a list of packet trace
    """
    nbPacket = []
    names = ['Authentification', 'Appel audio-vidéo', 'Partage d\'écran' , 'Messagerie']
    for traces in traceList:
        nbPacket.append(CountDNSPackets(traces))
    
    plt.bar(names, nbPacket)
    plt.xticks(rotation=30)
    plt.title("Nombre de noms de domaines résolus par trace")
    plt.tight_layout()
    #plt.savefig("graphs/dns_bar_graph.pdf")
    plt.show()
    
    #plot a graph with the amount of dns packets per second for seven minutes
    fig, ax = plt.subplots(2, 2, sharey=True)
    fig.suptitle("Nombre de paquets DNS par seconde par trace")

    colors = ["tab:blue","tab:red", "tab:green", "tab:orange"]
    for i in range(len(traceList)):
        print("capture de :" + traceList[i])
        timeOfPacket = np.zeros(90)
        
        captotal = ps.FileCapture(traceList[i])
        firstPacketTime = captotal[0].sniff_time
        captotal.close()
        
        cap = ps.FileCapture(traceList[i], display_filter='dns')
        for pkt in cap:
            timeOfPacket[int((pkt.sniff_time-firstPacketTime).total_seconds())] += 1
        
        ax[int(i/2), i%2].set_title(names[i])
        ax[int(i/2), i%2].plot(timeOfPacket, color = colors[i], alpha = 0.9)
        ax[int(i/2), i%2].grid()

        cap.close()
    for a in ax.flat:
        a.set(xlabel='Temps [s]', ylabel='Nombre de paquets')
    for a in ax.flat:
        a.label_outer()

    plt.tight_layout()
    #plt.savefig("graphs/dns_packetTime_graph.pdf")
    plt.show()
    
def dnsDomainNameResolved(trace):
        cap = ps.FileCapture(trace, display_filter='dns')
        print("capture de :" + trace)
        data = {} # dictionnaire pour stocker proportion de chaque adresse
        for pkt in cap:
            q = pkt.dns.qry_name
            if (q not in data.keys()):
                data[q] = 1
            else :
                data[q] +=1 
            print(q)
        cap.close()
        """
        print("RECAP : ", data)
        for k in data.keys():
            print("- {} ({})".format(k,data[k]))
        """
        print("=======================================")
        
def dnsAuthoritativeServer(trace):
    cap = ps.FileCapture(trace, display_filter='dns')
    print("capture de :" + trace)
    for pkt in cap:
        if pkt.dns.flags_response == "1":
            if int(pkt.dns.count_auth_rr) > 0:
                    print(pkt.dns.resp_name)
    cap.close()
    print("=======================================")
    
def dnsGetTypeOfQuery(trace):
    cap = ps.FileCapture(trace, display_filter='dns')
    print("capture de :" + trace)
    for pkt in cap:
            print(pkt.dns.flags_recdesired)
    cap.close()
    print("=======================================")
    
def dnsAdditionalRecords(trace):
    cap = ps.FileCapture(trace, display_filter='dns')
    print("capture de :" + trace)
    for pkt in cap:
            print(pkt.dns.field_names)
    cap.close()
    print("=======================================")
    
if __name__ == '__main__':

    # Fichier de captures    
    onlyfiles = ["packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng",
                 "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng",
                 "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng",
                 "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng",
                ]
        
    
    if sys.argv[1] == "graph":
        graphmaker(onlyfiles)
    elif sys.argv[1] == "domain":
        for traces in onlyfiles:
            dnsDomainNameResolved(traces)
    elif sys.argv[1] == "authoritative":
        for traces in onlyfiles:
            dnsAuthoritativeServer(traces)
    elif sys.argv[1] == "type":
        for traces in onlyfiles:
            dnsGetTypeOfQuery(traces)
    elif sys.argv[1] == "additional":
        for traces in onlyfiles:
            dnsAdditionalRecords(traces)
    else:    
        print("\n=======================================")
        for traces in onlyfiles:
            print("nom de domaines résolus: " + str(CountDNSPackets(traces)))
            #print("time of packet capture " + str(computeexperimentTime(traces))) 
            cap = ps.FileCapture(traces)
            nbPacket = 0
            for pkt in cap:
                nbPacket += 1
            print("nombre de paquets total: " + str(nbPacket))
            cap.close()
            print("=======================================") 
    

    # Ajout : DNS horizontal

    dns_barh = False # mettre à True pour afficher graphique en batonnet horizontal

    if dns_barh : 

        f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
        f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
        f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
        f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"

        cap_login = ps.FileCapture(f_login, display_filter='dns')
        cap_call = ps.FileCapture(f_call, display_filter='dns')
        cap_screen = ps.FileCapture(f_screen, display_filter='dns')
        cap_msg = ps.FileCapture(f_msg, display_filter='dns')

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

