# spoofing.py

from scapy.all import *
from scapy.layers.inet import *

a = IP()
a.src = '8.8.8.8'
a.dst = '10.9.0.5'
b = ICMP()
p = a / b
send(p)
p.show()
