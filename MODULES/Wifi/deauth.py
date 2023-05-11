from scapy.layers.dot11 import Dot11Deauth
import time
from MODULES.write_to_file import add_to_current,add_to_logs
import datetime
# class to detect deauth attacks
class Deauth:
    def __init__(self):
        # declare unusual amount of packets
        self.packetThreshold = 10
        # decalre the time period to reset the count
        self.timeThreshold = 60
        # record of all received packets
        self.record = {'count': 0, 'time': time.time()}
        self.WARNING = '\033[91m'
        self.BOLD = '\033[1m'

    def detectDeauth(self,pkt):
        if pkt != None:
            # get the time difference between the packets
            current = time.time()-self.record['time']
            # check for deauth layer
            if Dot11Deauth in pkt:
                # increase the count if packet is detected
                self.record['count'] = self.record['count']+1
            # identify signature of deauth attack    
            if current < self.timeThreshold and self.record['count'] > 10:
                message=f" "+str(datetime.datetime.now())+"  "+"Warning! you just received unexpected amount of Deauth packets...Possible deauth attack"+"\n"
                add_to_current(message)
                add_to_logs(message)                  
                print(f'{self.WARNING}{self.BOLD}Warning! you just received unexpected amount of Deauth packets...Possible deauth attack')
            else:
                # if not an attack then just reset the record
                self.record['count'] = 0
                self.record['time'] = time.time()
