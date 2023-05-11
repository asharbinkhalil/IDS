#!/usr/bin/env python3
from flask import Flask, render_template
from MODULES.portScans import ScanDetector
from MODULES.pingOfDeath import PingOfDeath
from MODULES.landattack import landAttack
from MODULES.synflood import synFlood
from MODULES.ddos import Ddos
from MODULES.Wifi.deauth import Deauth
from MODULES.arp import arpSpoof
from MODULES.smurf import Smurf
from MODULES.idleScan import IDLEScanDetector
from MODULES.RogueDHCP import RogueDHCPServerDetector
from scapy.all import IP, sniff
import sys
from netifaces import interfaces
from flask import request

app = Flask(__name__, template_folder='templates')
app.secret_key = 'mysecretkey'

# Initialize IDS modules
print('Initializing...')
dummyPkt = IP(dst='123.123.123.123')
myIP = str(dummyPkt[IP].src)

scanObj=ScanDetector(myIP)
podObj=PingOfDeath(myIP)
synobj=synFlood(myIP)
ddosobj=Ddos(myIP)
deauthobj=Deauth()
arpobj=arpSpoof(myIP)
smurfobj=Smurf(myIP)
#idleobj=IDLEScanDetector("eth0")
#dhcp_detector = RogueDHCPServerDetector("eth0")



# Sniff packets and detect attacks
@app.route("/")
def index():
    return render_template('index.html', data=interfaces())

@app.route("/start")
def start_sniffing():
    def main(pkt):
        scanObj.oneForAll(pkt)
        podObj.podDetect(pkt)
        landAttack(pkt,myIP)
        ddosobj.detectDdos(pkt)
        synobj.detectSyn(pkt)
        deauthobj.detectDeauth(pkt)
        smurfobj.detectSmurf(pkt)
        #dhcp_detector.start_sniffing()
    interface = request.args.get('interface')
    # Start sniffing
    #interface=sys.argv[1]
    print('IDS is online and looking for attacks on ', interface)
    sniff(iface=interface, prn=main)


@app.route('/alerts')
def display():
    file_path = 'LOGS/current.txt'
    data = []
    with open(file_path, 'r') as file:
        for line in file:
            data.append(line.strip())
    #copy_file('example.txt','log.txt')
    return render_template('index.html', data=data)



@app.route('/previous-logs')
def display_all():
    file_path = 'LOGS/logs.txt'
    data = []
    with open(file_path, 'r') as file:
        for line in file:
            data.append(line.strip())
    #copy_file('example.txt','log.txt')
    return render_template('index.html', data=data)

if __name__ == '__main__':
    with open('LOGS/current.txt', 'w') as f:    #empty the current file at start of program.
        pass
    app.run(debug=True)