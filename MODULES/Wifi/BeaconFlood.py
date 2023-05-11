from scapy.layers.dot11 import Dot11Beacon
import time

class BeaconFlood:
    def __init__(self):
        # declare the threshold for number of packets
        self.packetThreshold = 1000
        # declare the time period to reset the count
        self.timeThreshold = 60
        # record of all received packets
        self.record = {'count': 0, 'time': time.time()}
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    def detectBeaconFlood(self,pkt):
        if pkt != None:
            # get the time difference between the packets
            current = time.time()-self.record['time']
            # check for beacon layer
            if Dot11Beacon in pkt:
                # increase the count if packet is detected
                self.record['count'] = self.record['count']+1
            # identify signature of beacon flooding attack
            if current < self.timeThreshold and self.record['count'] > self.packetThreshold:
                print(f'{self.WARNING}{self.BOLD}Warning! you just received a large number of Beacon frames...Possible Beacon Flooding Attack')
            else:
                # if not an attack then just reset the record
                self.record['count'] = 0
                self.record['time'] = time.time()
