from scapy.layers.inet import IP, TCP
from MODULES.write_to_file import add_to_current,add_to_logs
import datetime
# class to detect syn flood attack
class synFlood:
    def __init__(self,hostIP):
        # dictionary to keep track of IPs that only sent syn packets and never completed connections
        self.flood = {}
        self.myIP=hostIP
        self.synAttacked = False
        # if found more than 50 syn packets
        self.threshold = 50
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    def detectSyn(self, pkt):
        if not self.synAttacked:
            if IP in pkt:
                # get ip from packet
                ip = pkt[IP].src
                if ip != None and TCP in pkt and pkt[IP].dst == self.myIP:
                    flag = str(pkt[TCP].flags)
                    # check for syn packets
                    if flag == 'S':
                        # add to dictionary id new ip
                        if ip not in self.flood.keys():
                            self.flood[ip] = {'count': 1}
                        else:
                            # else just increase the amount of syn packets received from that IP
                            self.flood[ip]['count'] = self.flood[ip]['count']+1
                    # check for ack packets to see if any connection was completed
                    elif flag == 'A':
                        if ip in self.flood.keys():
                            count = self.flood[ip]['count']
                            self.flood[ip]['count'] = count-1
                            # if connection was completed then remove the IP from records
                            if count <= 0:
                                del self.flood[ip]
                        else:
                            pass

                    for address in self.flood.keys():
                        if self.flood[address]['count'] > self.threshold:
                            message=f" "+str(datetime.datetime.now())+"  "+"Warning! you may be under a syn-flood attack from IP:"+str(address)+"\n"
                            add_to_current(message)
                            add_to_logs(message)  
                            print(
                                f'{self.WARNING}{self.BOLD}Warning! you may be under a syn-flood attack from IP:'+str(address))
                            self.synAttacked = True
                            break

