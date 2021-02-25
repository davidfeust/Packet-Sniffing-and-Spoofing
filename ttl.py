# # ttl.py
#
from time import sleep

from scapy.layers.inet import *
from scapy.all import *

'''
In this task we use Scapy to estimate the distance,
in terms of number of routers, between our VM and a selected destination
in our case we choose 8.8.8.8 to be our destination. 
This is basically what is implemented by the traceroute tool. 
'''

a = IP()
a.dst = "8.8.8.8"
b = ICMP()
# here we changing each iteration the ttl and therefore we getting each router on our way with an icmp error
for i in range(30):
    sleep(2)
    a.ttl = i
    p = a / b
    send(p)
