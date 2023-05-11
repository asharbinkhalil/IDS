from scapy.layers.inet import IP
import time
from MODULES.write_to_file import add_to_current, add_to_logs
import datetime

class Ddos:
    def __init__(self, hostIP):
        # get host IP
        self.myIP = hostIP
        self.ddosAttacked = False
        # prepare record for all incoming packets
        self.pktRecord = {'count': 0, 'time': 0}
        # if packets more than 1000 packets/second
        self.threshold = 30
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'
        # initialize the anomaly detection algorithm
        self.mean_pkt_rate = 0.0
        self.std_pkt_rate = 0.0

    def detectDdos(self, pkt):
        if not self.ddosAttacked:
            # get the time between packets
            current = time.time() - self.pktRecord['time']
            if IP in pkt:
                ip = str(pkt[IP].dst)
                if ip != None and ip == self.myIP:
                    self.pktRecord['count'] += 1

            # update the mean and standard deviation of the packet rate
            self.mean_pkt_rate = 0.9 * self.mean_pkt_rate + 0.1 * (self.pktRecord['count'] / current)
            self.std_pkt_rate = 0.9 * self.std_pkt_rate + 0.1 * ((self.pktRecord['count'] / current) - self.mean_pkt_rate) ** 2

            # use the anomaly detection algorithm to detect unusual amounts of packets
            if (self.pktRecord['count'] / current) > (self.mean_pkt_rate + 3 * self.std_pkt_rate):
                message = f" {str(datetime.datetime.now())}  Warning! You are receiving unusual amounts of packets...Possible DDOS\n"
                add_to_current(message)
                add_to_logs(message)
                print(f'{self.WARNING}{self.BOLD}Warning! You are receiving unusual amounts of packets...Possible DDOS')
                self.ddosAttacked = True

            if current > 5:
                self.pktRecord['time'] = time.time()
                self.pktRecord['count'] = 0
