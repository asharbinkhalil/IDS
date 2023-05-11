from scapy.layers.dot11 import Dot11Beacon,Dot11
import time

class RogueAP:
    def __init__(self):
        # declare the time period to reset the count
        self.timeThreshold = 60
        # record of all received Access Point (AP) MAC addresses
        self.record = set()
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    def detectRogueAP(self,pkt):
        if pkt != None:
            # get the time difference between the packets
            current = time.time()-self.record['time']
            # check for beacon layer
            if Dot11Beacon in pkt:
                # get the AP MAC address
                ap_mac = pkt[Dot11].addr2
                # add the AP MAC address to the record set
                self.record.add(ap_mac)
            # identify signature of rogue AP
            if current < self.timeThreshold and len(self.record) > 1:
                print(f'{self.WARNING}{self.BOLD}Warning! multiple AP MAC addresses detected...Possible Rogue Access Point')
            else:
                # if not an attack then just reset the record
                self.record = set()
                self.record.add(ap_mac)
                self.record['time'] = time.time()
