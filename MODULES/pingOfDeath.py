from scapy.layers.inet import IP
from MODULES.write_to_file import add_to_current,add_to_logs
import datetime
# class to detect ping of death
class PingOfDeath:
    def __init__(self,hostIP):
        # dictionary to store size of all icmp packets from different IPs
        self.pod = {}
        self.myIP=hostIP
        # if size of a packet from a single IP is more than maximum alowed size
        self.sizethreshold = 65000
        self.podAttacked = False
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    def podDetect(self, pkt):
        if not self.podAttacked:
            if IP in pkt:
                ip = pkt[IP].src
                # check if the protocol of packets is ICMP(ping packet)
                if pkt[IP].proto == 1:
                    if ip != None and ip==self.myIP:
                        # check if ip address is already inside dictionary
                        if ip not in self.pod.keys():
                            self.pod[ip] = {'size': len(pkt)}
                        else:
                            # else just update the size of packets received from that IP
                            self.pod[ip]['size'] = self.pod[ip]['size'] + len(pkt)
                        # finally iterate over all IP addresses and see if anyone crosses the threshold
                        for target in self.pod.keys():
                            if self.pod[target]['size'] > self.sizethreshold:
                                message=f" "+str(datetime.datetime.now())+"  "+"Warning! You may have received a possible ping of death from IP "+target+"\n"
                                add_to_current(message)
                                add_to_logs(message)   
                                print(
                                    f'{self.WARNING}{self.BOLD}Warning! You may have received a possible ping of death from IP'+target)
                                self.podAttacked = True
                                break
                            