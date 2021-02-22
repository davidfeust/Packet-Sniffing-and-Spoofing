# SniffingAndThenSpoofing.py
from scapy.layers.inet import IP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import sniff, AsyncSniffer, send

# for i in dir(ICMP):
# print(i)
pkt = sniff(iface='br-9b889cd55d52', count=1, filter='icmp and src host 10.9.0.5')

dest = 0
source = 0
if pkt[0].haslayer(IP):
    dest = pkt[0].getlayer(IP).dst
    source = pkt[0].getlayer(IP).src
    id_p = pkt[0].getlayer(ICMP).id
    seq = pkt[0].getlayer(ICMP).seq

    print(dest, "dest")
    print(source, "source")
    print(id_p, "id_p")
    print(seq, "seq")

    a = IP(src=dest, dst=source)
    b = ICMP(type=0, id=id_p, seq=seq)
    send((a / b))  # /"-----------shallom----------"
