from .detect import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from collections import defaultdict
from queue import Queue
import threading

pkt_filter = Packet_filter()

class SniffPacket(QThread):
    packet_captured_signal = pyqtSignal(dict)
    def __init__(self):
        super().__init__()
        self.packet_list = {}
        self.packet_scoring = {}
        self.packet_ports = defaultdict(list)
        self.packet_queue = Queue(maxsize=2000)
        self.is_running = True
        self.pktdump = PcapWriter("/home/ramu/venv-env/ids_mini/database/history_capture.pcap", append=True, sync=True)

    def filtering_packets_attr(self):
        pkt = self.packet_queue.get()
        info = pkt_filter._filtering_packets_attr(pkt,self.packet_list,self.packet_scoring,self.packet_ports)
        if info: self.packet_captured_signal.emit(info)

    def push_in_queue(self,pkt):
        try:
            self.pktdump.write(pkt)
            if not self.packet_queue.full():
                self.packet_queue.put(pkt, block=False) 
        except:
            pass
    
    def processing_loop(self):
        while self.is_running:
            if not self.packet_queue.empty():
                pkt = self.packet_queue.get()
                info = pkt_filter._filtering_packets_attr(pkt, self.packet_list, self.packet_scoring, self.packet_ports)
                if info: 
                    self.packet_captured_signal.emit(dict(info))
                self.packet_queue.task_done()

    def run(self):
        self.process_thread = threading.Thread(target=self.processing_loop, daemon=True)
        self.process_thread.start()
        try:
            sniff(prn = self.push_in_queue,store=0,stop_filter=lambda x: not self.is_running)
        except Exception as e:
            print(e)
        return
    def show_packet(self):
        for key,value in self.packet_list.items(): print(key,value)
        return 
    def stop(self):
        self.is_running = False
        if hasattr(self, 'pktdump'):
            self.pktdump.close()
        self.quit()
        self.wait()