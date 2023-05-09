from scapy.layers.inet import IP
import time

# class to detect possible ddos
class Ddos:
    def __init__(self, hostIP):
        # get host IP
        self.myIP = hostIP
        self.ddosAttacked = False
        # prepare record for all incoming packets
        self.pktRecord = {'count': 0, 'time': 0}
        # if packets more than 1000 packets/second
        self.threshold = 1000
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    def detectDdos(self, pkt):
        if not self.ddosAttacked:
            # get the time between packets
            current = time.time()-self.pktRecord['time']
            if IP in pkt:
                ip = str(pkt[IP].dst)
                if ip != None and ip == self.myIP:
                    self.pktRecord['count'] += 1

            if self.pktRecord['count']/current > self.threshold:
                print(
                    f'{self.WARNING}{self.BOLD}Warning! You are receiveing unusual amounts of packets...Possible DDOS')
                self.ddosAttacked = True
            if current > 5:
                self.pktRecord['time'] = time.time()
                self.pktRecord['count'] = 0
