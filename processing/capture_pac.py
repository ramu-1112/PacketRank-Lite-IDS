from .detect import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from collections import defaultdict

pkt_filter = Packet_filter()

class SniffPacket(QThread):
    packet_captured_signal = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.packet_list = {}
        self.packet_scoring = {}
        self.packet_ports = defaultdict(list)
        self.is_running = True

    def filtering_packets_attr(self,pkt):
        info_src = pkt_filter._filtering_packets_attr(pkt,self.packet_list,self.packet_scoring,self.packet_ports)
        self.packet_captured_signal.emit(info_src)
    def run(self):
        sniff(prn = self.filtering_packets_attr,store=0,stop_filter=lambda x: not self.is_running)
        return
    def show_packet(self):
        for key,value in self.packet_list.items(): print(key,value)
        return 
    def stop(self):
        self.is_running = False
        self.wait()