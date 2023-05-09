#!/usr/bin/env python3
from scapy.all import IP,ICMP,send
pkt = IP(dst='192.168.0.255', src='192.168.0.102')/ICMP()
send(pkt, count=1)