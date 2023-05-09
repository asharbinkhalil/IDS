from scapy.layers.inet import IP, TCP
import time
# function to detect land attack


def landAttack(pkt, hostIP):
    WARNING = '\033[91m'
    BOLD = '\033[1m'
    # check for TCP and IP layers in packet
    if TCP in pkt:
        if IP in pkt:
            srcIp = pkt[IP].src
            dstIp = pkt[IP].dst
            srcPort = pkt[TCP].sport
            dstPort = pkt[TCP].dport
            if dstPort != None and srcPort != None and srcIp == hostIP:
                # if both source port and IP are same then alert
                if srcIp == dstIp and srcPort == dstPort:
                    #print(f'You just received a land attack packet from IP:'+str(srcIp))
                    print(f'{WARNING}{BOLD}You just received a land attack packet from IP:'+str(srcIp))
