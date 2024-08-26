import os
import subprocess
from scapy.all import sniff, wrpcap
import pyfiglet
import time

def display_header():
    figlet = pyfiglet.Figlet()
    ascii_art = figlet.renderText('WIFI NEXIS       scan analyze secure...')
    lines = ascii_art.split('\n')
    for line in lines:
     print(line)
     time.sleep(0.5)
    print('                                           Written by jesimiel')

def check_network_connection():
    result = subprocess.run(['nmcli', '-t', '-f', 'ACTIVE,SSID', 'dev', 'wifi'], capture_output=True, text=True)
    active_connections = [line.split(':')[1] for line in result.stdout.splitlines() if line.startswith('yes')]
    if not active_connections:
        print("No Wi-Fi connection detected. Please connect to a Wi-Fi network.")
        return None
    else:
        essid = active_connections[0]
        print(f"Running analysis on the {essid} network.")
        return essid

def capture_http_packets(interface):
    print('Checking for HTTP packets...')
    def packet_filter(packet):
        return packet.haslayer('HTTP')

    packets = sniff(iface=interface, filter="tcp port 80", prn=lambda x: x.summary(), timeout=15)
    wrpcap('http_packets.pcap', packets)

def check_wps(interface):
    print('Checking for WPS...')
    result = subprocess.run(['iw', 'dev', interface, 'scan'], capture_output=True, text=True)
    with open('scan_results.txt', 'w') as file:
        file.write(result.stdout)

    if 'WPS' in result.stdout:
        return True
    else:
        return False

def check_encryption_protocol(interface):
    print('Checking Encryption Protocol...')
    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
    with open('encryption_info.txt', 'w') as file:
        file.write(result.stdout)
    
    if 'WEP' in result.stdout or 'WPA' in result.stdout:
        return True
    else:
        return False

def recommend_fixes():
    os.system('clear')
    print('Analysis Results:')
    if os.path.exists('http_packets.pcap') and os.path.getsize('http_packets.pcap') > 0:
        print("Avoid sites running on HTTP; your login details could be stolen.")
    else:
        print("No HTTP packets detected.")
    
    if os.path.exists('scan_results.txt') and 'WPS' in open('scan_results.txt').read():
        print("Disable WPS to avoid brute force attacks.")
    else:
        print("WPS not detected.")
    
    if os.path.exists('encryption_info.txt'):
        encryption_info = open('encryption_info.txt').read()
        if 'WEP' in encryption_info or 'WPA' in encryption_info:
            print("Weak encryption protocol detected. Upgrade to WPA2/WPA3.")
        else:
            print("No weak encryption protocol detected.")
    
    if all([
        not os.path.exists('http_packets.pcap') or os.path.getsize('http_packets.pcap') == 0,
        not os.path.exists('scan_results.txt') or 'WPS' not in open('scan_results.txt').read(),
        not os.path.exists('encryption_info.txt') or ('WEP' not in open('encryption_info.txt').read() and 'WPA' not in open('encryption_info.txt').read())
    ]):
        print("Your Wi-Fi network is good to go.")

def main():
    while True:
        display_header()
        interface = "wlan0"  # Change this to your actual Wi-Fi interface name
        essid = check_network_connection()
        if essid:
            capture_http_packets(interface)
            wps_vulnerable = check_wps(interface)
            encryption_vulnerable = check_encryption_protocol(interface)
            recommend_fixes()

        while True:
            user_input = input("Press Enter to run the script again or 'x' to quit: ")
            if user_input == "":
                break
            elif user_input.lower() == "x":
                print("Exiting the script.")
                return
            else:
                print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
