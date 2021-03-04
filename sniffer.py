from scapy.all import *
from header import *


def print_pkt(pkt):
    pkt.show()


"""a different version of sniff packets with different type of filters using scapy"""

interface = INTERFACE
icmp_filter = 'icmp'
port_filter_tcp = 'tcp and src host 10.9.0.5 and dst port 23'
net_filter = 'net 128.0.0.0/1'

pkt = sniff(iface=interface, filter=icmp_filter, prn=print_pkt)

pkt = sniff(iface=interface, filter=net_filter, prn=print_pkt)

pkt = sniff(iface=interface, filter=port_filter_tcp, prn=print_pkt)

"""
run from terminal: sudo python3 sniffer.py
for testing run from host: ping 8.8.8.8
"""
