from scapy.all import PcapWriter

def clear_pcap(file):
    writer = PcapWriter(file, append=False, sync=True)
    writer.close()
    print("reset done")

files = ["database/tcp_capture.pcap", "database/udp-capture.pcap", "database/default.pcap"]
for f in files:
    clear_pcap(f)