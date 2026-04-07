from .detect import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from queue import Queue
from scoring.pkt_inform import Score
import socket
import threading
import csv
import pickle
import numpy as np
import time
import webview
import os


pkt_filter = Packet_filter()
score = Score()

class SniffPacket(QThread):
    attack_scoring = pyqtSignal(dict)
    def __init__(self):
        super().__init__()
        with open("/home/ramu/venv-env/ids_mini/ids_dashboard_sniff/scoring/ids_model.pkl","rb") as file:
            self.clf = pickle.load(file)
        with open("/home/ramu/venv-env/ids_mini/ids_dashboard_sniff/scoring/scaler.pkl","rb") as file:
            self.scaler = pickle.load(file)
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.packet_queue = Queue(maxsize=2000)
        self.is_running = True
        self.start_time = time.perf_counter()
        self.packet_filter = f"(ip or ip6 or icmp or tcp or udp) and not src host {self.local_ip} and dst host {self.local_ip}"
        self.pktdump_default = PcapWriter("/home/ramu/venv-env/ids_mini/ids_dashboard_sniff/database/default.pcap", append=True, sync=True)
        self.pktdump_tcp = PcapWriter("/home/ramu/venv-env/ids_mini/ids_dashboard_sniff/database/tcp_capture.pcap", append=True, sync=True)
        self.pktdump_udp = PcapWriter("/home/ramu/venv-env/ids_mini/ids_dashboard_sniff/database/udp-capture.pcap", append=True, sync=True)
        self.proto_mapping = {"TCP":self.pktdump_tcp,"UDP":self.pktdump_udp}
    def push_in_queue(self,pkt):
        try:
            if not self.packet_queue.full():
                self.packet_queue.put(pkt, block=False) 
        except:
            pass
    
    def processing_loop(self):
        while self.is_running:
            if not self.packet_queue.empty():
                pkt = self.packet_queue.get()
                pcap_file,info = pkt_filter._filtering_packets_attr(pkt, score.packet_lists, score.scoring_board, score.total_ports_board,time.perf_counter()-self.start_time)
                if info: 
                    if pcap_file in self.proto_mapping: self.proto_mapping[pcap_file].write(pkt)
                    else: self.pktdump_default.write(pkt)
                self.packet_queue.task_done()
    
    def sort_score(self,data):

        self.timer = threading.Timer(3,self.sort_score)
        self.timer.start()
    def run_after_10s(self,data):
        after_score = {}
        gui_data = {}
        for key,value in data.items():
            fl = False  
            value.packets_per_10s = value.total_packets - value.packet_last
            if value.packets_per_10s > 0: 
                fl = True
                value.duration = value.duration/value.packets_per_10s
            if fl: value.duration = 0; value.last_time = value.get_time
            value.packet_last = value.total_packets
            features = np.array([[
                value.packet_per_sec,
                value.duration,
                value.total_ports,
                value.total_packets,
                value.ack_raito
            ]])
            features_scaled = self.scaler.transform(features)
            percent = self.clf.predict_proba(features_scaled)
            attack_percentage = percent[0][1]*100
            after_score.update({value.src:attack_percentage})
            gui_data[key] = {
                "score": attack_percentage,
                "src":score.packet_lists[key].src,
                "dst":score.packet_lists[key].dst,
                "proto":score.packet_lists[key].proto,
                "dport":score.packet_lists[key].dport,
                "pps":value.packet_per_sec
            }
        after_score = dict(sorted(after_score.items(), key=lambda item: item[1],reverse = True))
        final_data = {k:gui_data[k] for k in after_score}
        self.attack_scoring.emit(final_data)
        self.timer = threading.Timer(10,self.run_after_10s,args=(score.scoring_board,))
        self.timer.start()

    def run(self):
        self.process_thread = threading.Thread(target=self.processing_loop, daemon=True)
        self.process_thread.start()
        self.timer = threading.Timer(10,self.run_after_10s,args=(score.scoring_board,))
        self.timer.start()
        try:
            sniff(filter = self.packet_filter,prn = self.push_in_queue,store=0,stop_filter=lambda x: not self.is_running)
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