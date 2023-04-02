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
    names = []
    for traces in traceList:
        nbPacket.append(CountDNSPackets(traces))
        names.append(traces.split("/")[1].split("_")[1])
    
    plt.bar(names, nbPacket)
    plt.xticks(rotation=30)
    plt.title("Nombre de nom de domaines résolus par trace")
    plt.tight_layout()
    plt.savefig("graphs/dns_bar_graph.png")
    
    #plot a graph with the amount of dns packets per second for seven minutes
    fig, ax = plt.subplots(len(traceList), 1, figsize=(10, 10))
    for i in range(len(traceList)):
        print("capture de :" + traceList[i])
        timeOfPacket = np.zeros(60*7)
        totalTime = [i for i in range(60*7)]
        
        captotal = ps.FileCapture(traceList[i])
        firstPacketTime = captotal[0].sniff_time
        captotal.close()
        
        cap = ps.FileCapture(traceList[i], display_filter='dns')
        for pkt in cap:
            timeOfPacket[int((pkt.sniff_time-firstPacketTime).total_seconds())] += 1
        
        ax[i].set_title(traceList[i].split("/")[1].split("_")[1])      
        ax[i].plot(timeOfPacket)
        ax[i].grid()

        
        
        cap.close()
    plt.tight_layout()
    plt.savefig("graphs/dns_packetTime_graph.png")
    
if __name__ == '__main__':
    onlyfiles = [f for f in listdir("packet_traces") if isfile("packet_traces/" + f)]
    # print(onlyfiles)
    for i in range(len(onlyfiles)):
        onlyfiles[i] = "packet_traces/" + onlyfiles[i]
        
    
    if sys.argv[1] == "graph":
        graphmaker(onlyfiles)
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
