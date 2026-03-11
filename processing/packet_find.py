from scapy.all import PcapReader

class Packet_query:
    def __init__(self):
        self.file_query = {"TCP":"/home/ramu/venv-env/ids_mini/database/tcp_capture.pcap",
                           "UDP":"/home/ramu/venv-env/ids_mini/database/udp-capture.pcap",
                           "default":"/home/ramu/venv-env/ids_mini/database/default.pcap"}
    def search_packet(self,ip,protocol):
        with PcapReader(self.file_query[protocol]) as reader: pass
            