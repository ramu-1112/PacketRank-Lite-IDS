from scapy.all import PcapReader,IP,IPv6
from .detect import Packet_filter

table = Packet_filter()

class Packet_query:
    def __init__(self):
        self.file_query = {"TCP":"/home/ramu/venv-env/ids_mini/database/tcp_capture.pcap",
                           "UDP":"/home/ramu/venv-env/ids_mini/database/udp-capture.pcap",
                           "default":"/home/ramu/venv-env/ids_mini/database/default.pcap"}
        self.text = "==============================================="
    def search_packet(self,ip,protocol):
        meta_data = ""
        idx = 1
        with PcapReader(self.file_query[protocol]) as reader:
            for pkt in reader:
                if IP in pkt:
                    meta_data += self.queryv4(pkt,ip)
                    idx+= 1
                elif IPv6 in pkt:
                    meta_data += self.queryv6(pkt,ip)
                    idx+=1
                else: pass
            if idx > 1: return meta_data
            else: return "Packet not found!"

    def queryv4(self,pkt,ip):
        if pkt[IP].src == ip:
            return self.text + "\n" + pkt.show(dump=True) +"\n"
        else: return ""
            
    def queryv6(self,pkt,ip):
        if pkt[IPv6].src == ip:
            return self.text + "\n" + pkt.show(dump=True) + "\n"
        else: return ""