from detect import *
from collections import defaultdict

pkt_filter = Packet_filter()

class SniffPacket:
    def __init__(self):
        self.packet_list = {}
        self.packet_scoring = {}
        self.packet_ports = defaultdict(list)
    
    def capture_packets(self,times):
        capture = sniff(prn = lambda pkt: pkt_filter.filtering_packets_attr(pkt,self.packet_list,self.packet_scoring,self.packet_ports),count = times,store=0)
        return
    def show_packet(self):
        for key,value in self.packet_list.items(): print(key,value)
        return 
    
sni = SniffPacket()
sni.capture_packets(5)
sni.show_packet()