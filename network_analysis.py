import pyshark
import matplotlib.pyplot as plt
import numpy as np
 
# Affiche sur la sortie standard les différentes adresses des 4 scénarios décrits dans le rapport
# et leur pourcentage associé
def get_addresses():
    f_login = "packet_traces/M_Linux/FileCapture_Any_LaunchAndLogin.pcapng"
    f_call = "packet_traces/M_Linux/FileCapture_Any_Scenario2_Mathieu.pcapng"
    f_screen = "packet_traces/M_Linux/FileCapture_Any_Scenario3_Mathieu.pcapng"
    f_msg = "packet_traces/M_Linux/FileCapture_Any_Scenario4_Mathieu.pcapng"

    cap_login = pyshark.FileCapture(f_login)
    cap_call = pyshark.FileCapture(f_call)
    cap_screen = pyshark.FileCapture(f_screen)
    cap_msg = pyshark.FileCapture(f_msg)


    caps = [cap_login, cap_call, cap_screen, cap_msg]


    data = {}

    for cap in caps:
        for pkt in cap:
            try : 
                # Source
                src = pkt.ip.src
                if(src not in data.keys()):
                    data[src] = 1
                else:
                    data[src] += 1
                # Destination
                dst = pkt.ip.dst
                if(dst not in data.keys()):
                    data[dst] = 1
                else:
                    data[dst] += 1
            except:
                continue


    sorted_addresses = sorted(data, key=data.get, reverse=True)
    sorted_addresses.remove('10.0.2.15') #adresse de la machine Fedora
    data.pop('10.0.2.15')
    for i in range(len(sorted_addresses)):
        prct = (data[sorted_addresses[i]] / np.sum(list(data.values())) ) *100 # pourcentage de fois que cette adresse est présente
        print("- `{}` ({:.4f} %)".format(sorted_addresses[i], prct))


if __name__ == '__main__':
    get_addresses()