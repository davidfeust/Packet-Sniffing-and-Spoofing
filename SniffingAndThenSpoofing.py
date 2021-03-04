# SniffingAndThenSpoofing.py
from scapy.layers.inet import IP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import sniff, AsyncSniffer, send
from header import *

'''
In this task, we have been asked to sniff and spoof packets.
In one of the machines in our VM we ping an IP “X”(meaning some ip, in our example is 8.8.8.8 / 1.2.3.4 / 10.9.0.99). 
This will generate an ICMP echo request packet.
If X is alive, the ping program will receive an echo reply,
and print out the response. our sniff-and-then-spoof program runs on the VM,
which monitors the LAN through packet sniffing. Whenever it sees an ICMP echo request,
regardless of what the target IP address is, our program immediately sends out an echo reply 
using the packet spoofing technique. Therefore, regardless of whether machine X is alive or not, 
the ping program will always receive a reply, indicating that X is alive. 
'''

# sniff the packets
pkt = sniff(iface=INTERFACE, count=1, filter='icmp and src host 10.9.0.5')

dest = 0
source = 0
# collect the information from the packet
if pkt[0].haslayer(IP) and pkt[0].haslayer(ICMP):
    ip_layer = pkt[0].getlayer(IP)
    icmp_layer = pkt[0].getlayer(ICMP)

    dest = ip_layer.dst
    source = ip_layer.src
    id_p = icmp_layer.id
    seq = icmp_layer.seq

    print(dest, "dest")
    print(source, "source")
    print(id_p, "id_p")
    print(seq, "seq")

    # send a spoof packet to the collected src ip
    a = IP(src=dest, dst=source)
    b = ICMP(type=0, id=id_p, seq=seq)
    send((a / b))  # /"-----------shallom----------"

# run here: sudo python3 SniffingAndThenSpoofing.py
# for testing run from host container:
# ping 8.8.8.8 -c 1
