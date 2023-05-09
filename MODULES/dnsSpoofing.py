from scapy.all import DNSRR,DNS
import re

class DnsSpoof:
    def __init__(self):
        self.dns_cache = {}

    def detectDnsSpoof(self, pkt):
        if pkt != None:
            # Check if packet is a DNS response
            if pkt.haslayer(DNSRR) and pkt[DNS].qr == 1:
                # Check if the DNS response matches a known entry in the cache
                for rr in pkt[DNS].an:
                    if rr.type == 1:
                        domain = rr.rrname.decode('utf-8')
                        ip = rr.rdata
                        if domain in self.dns_cache and self.dns_cache[domain] != ip:
                            print(f"DNS Spoofing detected for domain {domain}. Original IP: {self.dns_cache[domain]}, Spoofed IP: {ip}")
                        else:
                            self.dns_cache[domain] = ip
