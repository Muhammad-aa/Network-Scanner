# This is a script that scans a device's connectivity and discovers all other devices connected to the same Network.
# Before Attempting to run this program, Please install Python from: https://Python.org/downloads.
# After installing Python, install Scapy from the CLI using: Pip install scapy.
# Finally, install npcap from: https://npcap.com/#download. You're all set.
# Pattern for Execution: [Python version] [Program Name] [-r] [Network portion of IP].1/24
# For Example, if my IP Address is 129.186.0.189. I would run it like:
# Example: Python3 Network_scanner.py -r 129.186.0.1/24.
# OR
# Example: Python3 Network_scanner.py --range 129.186.0.1/24.

import scapy.all as scapy            # This is a Library that helps with Packet Manipulations for Computer Networks.
import argparse                      # This is a Library that helps us to handle user Input from CLI (Command Line Interface).
from datetime import date, datetime  # This Library helps us work with and Date and Time.

# Function to get user arguments from CLI
def get_user_parameters():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--range", dest="ip", help="Specify IP range to scan. Use --help for more info.")
    (options) = parser.parse_args()
    if not options.ip:
        parser.error("IP range not specified.")
    return options

# Function that scans your IP and discovers all clients connected to the same network as you.
def scanner(ip_address):
    arp_requests = scapy.ARP(pdst=ip_address)           # This Line of code creates a request with a specified destination IP.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")    # This Line of code is for creating a Broadcast Frame.
    arp_requests_broadcast = broadcast/arp_requests     # This Line Combines the packets in one.
    answered_packets = scapy.srp(arp_requests_broadcast, timeout=1, verbose=False)[0]  # This Line of code returns the answered packets after a request has been sent.
    client_list = []
    for element in answered_packets:
        client_dict = {"ip": element[1].psrc, "MAC":element[1].hwsrc }
        client_list.append(client_dict)
    return client_list

# Function to Print the results (All Ips and MAC addresses).
def print_result(netscan_results):
    todays_date = date.today() # This Line of code gets us today's date.
    now = datetime.now()       # This Line of code gets us the Time.
    current_time = now.strftime("%H:%M:%S")
    print(" Network Scanner by Abdullah Muhammad..\t", "Date:", todays_date, "\t", "Time:", current_time + "\n")
    print(" IP\t\t\tMAC Address\n-----------------------------------------")
    for each_result in netscan_results:
        print(each_result["ip"] + "\t\t" + each_result["MAC"])

# Execution
options = get_user_parameters()
scan_result = scanner(options.ip)
print_result(scan_result)
