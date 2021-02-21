# # ttl.py
#
from scapy.all import *
from scapy.layers.inet import *

ans, unans = sr(IP(dst='8.8.8.8', ttl=(4, 25), id=RandShort()) / TCP(flags=0x2))
for snd, rcv in ans:
    print(snd.ttl, rcv.src, isinstance(rcv.payload, TCP))

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
# # a = IP()
# # a.src = '10.9.0.5'
# # a.dst = "8.8.8.8"
# # b = TCP()
# # ans = None
# # p = (a / b)
# dest = "8.8.8.8"
# x = 1
# while True:
#     print(x)
#     src = send_tcp(x)
#     x += 1
#     if src == dest:
#         break
