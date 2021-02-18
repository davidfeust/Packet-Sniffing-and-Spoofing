from scapy.layers.inet import *
from scapy.all import *


def print_pkt(pkt):
    pkt.show()


# pkt = sniff(iface='br-cf084e3006a0', filter='icmp', prn=print_pkt)
# pkt = sniff(iface='br-cf084e3006a0', filter='src host 10.9.0.5 and dst port 23', prn=print_pkt)
# send(IP(dst="10.9.0.1")/UDP(dport=23)/Raw(load="abc"))

# pkt = sniff(iface='br-cf084e3006a0', filter='icmp', prn=print_pkt)


pkt = sniff(iface='br-cf084e3006a0', filter='net 128.230.0.0/16', prn=print_pkt)
