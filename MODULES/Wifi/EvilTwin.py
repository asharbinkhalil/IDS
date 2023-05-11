from scapy.layers.dot11 import Dot11Beacon,Dot11Elt,Dot11
import time

class EvilTwin:
    def __init__(self):
        # declare the time period to reset the count
        self.timeThreshold = 60
        # record of all received Access Point (AP) MAC addresses
        self.record = {'ssid': '', 'mac': '', 'time': time.time()}
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    def detectEvilTwin(self,pkt):
        if pkt != None:
            # get the time difference between the packets
            current = time.time()-self.record['time']
            # check for beacon layer
            if Dot11Beacon in pkt:
                # get the AP SSID and MAC address
                ap_ssid = pkt[Dot11Elt].info.decode()
                ap_mac = pkt[Dot11].addr2
                # update the record if the SSID has changed
                if self.record['ssid'] != ap_ssid:
                    self.record['ssid'] = ap_ssid
                    self.record['mac'] = ap_mac
                    self.record['time'] = time.time()
                # identify signature of evil twin attack
                if current < self.timeThreshold and ap_ssid == self.record['ssid'] and ap_mac != self.record['mac']:
                    print(f'{self.WARNING}{self.BOLD}Warning! MAC address of the AP in the Beacon frames is different...Possible Evil Twin Attack')
                else:
                    # if not an attack then just reset the record
                    self.record['ssid'] = ap_ssid
                    self.record['mac'] = ap_mac
                    self.record['time'] = time.time()
