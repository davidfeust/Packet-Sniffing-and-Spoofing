# # ttl.py
#
from scapy.all import *
from scapy.layers.inet import *
from scapy.all import *

a = IP(dst="8.8.8.8")
b = ICMP()
for i in range(1, 28):
    a.ttl = i
    p = a / b
    send(p)


# import time
#
# resp = []
# for t in range(1, 30):
#     ip = IP(src="10.9.0.5", dst='8.8.8.8', ttl=t, id=RandShort())
#     ts = time.time()
#     r = sr1(ip / ICMP(), retry=1, timeout=3)
#     te = time.time()
#     resp.append((t, r, (te - ts) * 1000))
#     if r and r.src == '8.8.8.8':
#         break
# print(len(resp), 'responses')
# hostname = "google.com"
# for i in range(1, 28):
#     pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
#     # Send the packet and get a reply
#     reply = sr1(pkt, verbose=0, timeout=3)
#     if reply is None:
#         # No reply =(
#         break
#     elif reply.type == 3:
#         # We've reached our destination
#         print("Done!", reply.src)
#         break
#     else:
#         # We're in the middle somewhere
#         print("%d hops away: " % i, reply.src)

# ans, unans = sr(IP(dst="8.8.8.8", ttl=(4, 25), id=RandShort()) / TCP(flags=0x2))
#
# for snd, rcv in ans:
#     print(snd.ttl, rcv.src, isinstance(rcv.payload, TCP))
# ans, unans = sr(IP(dst='8.8.8.8', ttl=(4, 25), id=RandShort()) / TCP(flags=0x2))
# for snd, rcv in ans:
#     print(snd.ttl, rcv.src, isinstance(rcv.payload, TCP))

# a = IP()
# a.dst = "1.2.3.4"
# a.ttl = 3
# b = ICMP()
# send(a/b)

#
#
# def parse_pkt(packet):
#     print(type(packet))
#
#
# def send_tcp(ttl):
#
#      ans= sr1(IP(dst="8.8.8.8", ttl=ttl)/ICMP()/"ttl find")
#      ans.show()
#      return ans
#     # packet.ttl = ttl
#     ans, unans = sr(IP(dst="8.8.8.8", ttl=ttl) / ICMP())
#     src = ans[0][1].src
#     print(src)
#     return src
#     # send(packet)
#     # ans.summary(lambda s, r: r.sprintf("%IP.src%"))
#
#     # result[0].show()
#     # print(type(result[0]))
#     # return result[0][1]
#
#
# def send_tcp(ttl):
# a.src = '10.9.0.5'
# traceroute("8.8.8.8")
#
# const_dest = "8.8.8.8"
# a = IP(dst=const_dest, ttl=1)
# b = ICMP()
# ans = None
# p = (a / b)
# x = 1
#
# while True:
#     # print(x)
#     a = IP(dst=const_dest, ttl=x)
#     b = ICMP()
#     p = (a / b)
#     r = sr1(p, retry=1, timeout=3)
#     print(type(r))
#     if r.src == const_dest or x > 30:
#         break
#     x = x + 1
