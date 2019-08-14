import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="specify IP or IP range", dest="target", action="store", type=str)
    options = parser.parse_args()
    return options

def show_results(ans_clients):
    print("IP\t\t\tMAC\n-----------------------------------------")
    for client in ans_clients:
        print(client["ip"] + "\t\t" + client["mac"])

def scanner(ip):
    arp_pkt = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_pkt_broadcast = broadcast / arp_pkt
    ans = scapy.srp(arp_pkt_broadcast, timeout=1, verbose=False)[0]
    clients = []
    for a in ans:
        clients_dict = {"ip":a[1].pdst, "mac":a[1].hwsrc}
        clients.append(clients_dict)
    return clients

options = get_arguments()
clients = scanner(options.target)
show_results(clients)