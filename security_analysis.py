import pyshark
import matplotlib.pyplot as plt
import numpy as np

# voir description des scénarios rapport

f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"

cap_login = pyshark.FileCapture(f_login, display_filter='dns', use_json=True)
cap_call = pyshark.FileCapture(f_call, display_filter='dns', use_json=True)
cap_screen = pyshark.FileCapture(f_screen, display_filter='dns', use_json=True)
cap_msg = pyshark.FileCapture(f_msg, display_filter='dns', use_json=True)

### VERIFICATION DNS SECURISE (extension DNSSEC)

count = 0
for cap in [cap_login,cap_call,cap_screen,cap_msg]:
    for pkt in cap:
        if(pkt.dns.add_rr != '0'):
            count +=1 
            print("Extension détectée ! ")
            print(pkt)

print("Utilisation de l'extension DNSSEC : " , count!=0)


