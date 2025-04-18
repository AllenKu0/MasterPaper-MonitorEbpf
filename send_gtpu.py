# send_gtpu.py
from scapy.all import *

# 構造 GTP-U 封包 (簡單假裝)
pkt = Ether()/IP(dst="10.1.0.25")/UDP(dport=2152, sport=12345)/Raw(b"\x30" + b"\x00"*10)

sendp(pkt, iface="enp6s18")