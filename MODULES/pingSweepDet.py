from scapy.all import ICMP,IP
from MODULES.write_to_file import add_to_current,add_to_logs
class PingSweep:
    def __init__(self, threshold=10):
        self.threshold = threshold
        self.source_ips = {}

    def detectPingSweep(self, pkt):
        if pkt != None:
            # Check if packet is an ICMP Echo Request
            if ICMP in pkt:
                if pkt[ICMP].type == 8:
                    src_ip = pkt[IP].src

                    # If this source IP has sent more than the threshold number of ICMP Echo Requests, then it's a ping sweep
                    if src_ip in self.source_ips and self.source_ips[src_ip] >= self.threshold:
                        message=f"Ping sweep detected from {src_ip}"+"\n"
                        add_to_current(message)
                        add_to_logs(message)   
                        print(f"Ping sweep detected from {src_ip}")
                    else:
                        if src_ip in self.source_ips:
                            self.source_ips[src_ip] += 1
                        else:
                            self.source_ips[src_ip] = 1
