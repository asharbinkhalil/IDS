from scapy.all import IP, Ether, ARP, srp, sniff
from MODULES.write_to_file import add_to_current,add_to_logs
import datetime
# class to identify case of spoofed IP address
class arpSpoof:
    def __init__(self, hostip):
        self.myIP = hostip
        self.arpAttacked = False
        self.arpTable = {} # Custom arp table
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    def detectSpoof(self, pkt):
        if not self.arpAttacked:
            # check for Ether and IP layers in packet and get source IP and mac address
            if Ether in pkt:
                srcMac = pkt[Ether].src
                if IP in pkt:
                    srcIP = pkt[IP].src
                    # currently only identifies spoofed IP on LAN network i.e addresses starting with 192
                    if srcIP[:3] == '192' and srcIP != self.myIP:
                        # if the IP does not exist on out custom arp table then 
                        # send out an arp request to get the real Mac address of source IP of Packet 
                        if srcIP not in self.arpTable:
                            arp = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=srcIP)
                            ans, _ = srp(arp, timeout=1, verbose=False)
                            try:
                                mac = ans[0][1][ARP].hwsrc
                                self.arpTable[srcIP] = mac
                            except:
                                self.arpTable[srcIP] = None
                    # if the Mac addresses don't match then alert
                    if self.arpTable[srcIP] != srcMac:
                        message=f"Warning! You just receievd a packet with spoofed IP address"+"\n"
                        add_to_current(message)
                        add_to_logs(message)                       
                        print(
                            f'{self.WARNING}{self.BOLD}Warning! You just receievd a packet with spoofed IP address')
                        self.arpAttacked = True
