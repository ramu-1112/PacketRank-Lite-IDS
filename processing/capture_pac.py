from scapy.all import IP,TCP,sniff
import sqlite3
from detect import filter
import time

def packet_handle(pkt):
    length = len(pkt)
    src = dst = proto =""
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = str(pkt[IP].proto)
    print(src,dst)
idx = 0
capture = sniff(prn=packet_handle,store=False,count=5)



