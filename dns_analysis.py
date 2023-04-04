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
    # print(capture[0].dns.qry_name)
    
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
    names = ["visioconférence micro+video", "visioconférence partage écran",
             "messagerie intégrée", "lancement et connexion a l'appli"]
    for traces in traceList:
        nbPacket.append(CountDNSPackets(traces))
    
    plt.bar(names, nbPacket)
    plt.xticks(rotation=30)
    plt.title("Nombre de noms de domaines résolus par trace")
    plt.tight_layout()
    plt.savefig("graphs/dns_bar_graph.png")
    
    #plot a graph with the amount of dns packets per second for seven minutes
    fig, ax = plt.subplots(2, 2, sharey=True)
    fig.suptitle("Nombre de paquets DNS par seconde par trace")
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
        ax[int(i/2), i%2].plot(timeOfPacket)
        ax[int(i/2), i%2].grid()

        
        
        cap.close()
    for a in ax.flat:
        a.set(xlabel='temps (s)', ylabel='nombre de paquets')
    for a in ax.flat:
        a.label_outer()
    plt.tight_layout()
    plt.savefig("graphs/dns_packetTime_graph.png")
    
def dnsDomainNameResolved(trace):
        cap = ps.FileCapture(trace, display_filter='dns')
        print("capture de :" + trace)
        for pkt in cap:
            print(pkt.dns.qry_name)
        cap.close()
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
            print(pkt.dns.qry_type)
    cap.close()
    print("=======================================")
    
if __name__ == '__main__':
    onlyfiles = ["packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng",
                 "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng",
                 "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng",
                 "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"]
        
    
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
