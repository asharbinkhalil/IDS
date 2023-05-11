#!/usr/bin/env python3
from scapy.all import IP,ICMP,send
pkt = IP(dst='10.0.2.255', src='10.0.2.15')/ICMP()
send(pkt, count=1)