from scapy.all import DHCP,Ether,sniff
from MODULES.write_to_file import add_to_current,add_to_logs
class RogueDHCPServerDetector:
    def __init__(self, interface):
        self.interface = interface
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'
        self.dhcp_servers = []

    def dhcp_request_handler(self, pkt):
        if pkt[DHCP] and pkt[DHCP].options[0][1] == 3: # check if DHCP request
            client_mac = pkt[Ether].src
            if client_mac not in self.dhcp_servers:
                self.dhcp_servers.append(client_mac)
                message=f"Warning! Possible rogue DHCP server detected with MAC address: {client_mac}"+"\n"
                add_to_current(message)
                add_to_logs(message)   
                print(f"{self.WARNING}{self.BOLD}Warning! Possible rogue DHCP server detected with MAC address: {client_mac}")

    def start_sniffing(self):
        # Start sniffing for DHCP requests on the specified interface
        sniff(filter="udp and (port 67 or 68)", prn=self.dhcp_request_handler, iface=self.interface)
