from scapy.all import *


def print_pkt(pkt):
    pkt.show()


"""a different version of sniff packets with different type of filters using scapy"""

interface = 'br-cf084e3006a0'
icmp_filter = 'icmp'
port_filter = 'src host 10.9.0.5 and dst port 23'
net_filter = 'net 128.230.0.0/16'

pkt = sniff(iface=interface, filter=icmp_filter, prn=print_pkt)

pkt = sniff(iface=interface, filter=port_filter, prn=print_pkt)

pkt = sniff(iface=interface, filter=net_filter, prn=print_pkt)
