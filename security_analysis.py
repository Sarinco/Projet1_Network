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