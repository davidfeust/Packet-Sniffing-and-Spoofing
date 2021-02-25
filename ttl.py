# # ttl.py
#
from time import sleep

from scapy.layers.inet import *
from scapy.all import *

a = IP()
a.dst = "8.8.8.8"

b = ICMP()
for i in range(30):
    sleep(2)
    a.ttl = i
    p = a / b
    send(p)