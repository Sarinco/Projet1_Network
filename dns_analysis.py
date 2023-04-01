import pyshark as ps
import numpy as np
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
    
    
if __name__ == '__main__':
    onlyfiles = [f for f in listdir("packet_traces") if isfile("packet_traces/" + f)]
    # print(onlyfiles)
    print("\n=======================================")
    for traces in onlyfiles:
        print("nom de domaines résolus: " + str(CountDNSPackets("packet_traces/" + traces)))
        print("time of packet capture " + str(computeexperimentTime("packet_traces/" + traces))) 
        print("=======================================") 
