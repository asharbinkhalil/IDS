from scapy.all import IP

class IDLEScanDetector:
    def __init__(self, interface):
        self.interface = interface
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    def detect_idle_scan(self, pkt):
        if pkt != None:
            # check if the packet is an IP packet
            if IP in pkt:
                # check if the packet has the IP flags set to "DF" (Don't Fragment)
                if pkt[IP].flags == "DF":
                    # check if the packet's TTL is greater than the default TTL
                    if pkt[IP].ttl > 64:
                        print(
                            f'{self.WARNING}{self.BOLD}Warning! Possible IDLE scan detected from IP address: {pkt[IP].src}')
