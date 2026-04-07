from scapy.all import IP,TCP,UDP,IPv6,sniff,PcapWriter
import csv
import time 
class Scoring_packet_arg:
    def __init__(self,src,freq,ack_raito):
        self.src = src
        self.get_time =self.last_time= time.perf_counter()
        self.freq = freq
        self.ack_raito = ack_raito
        self.packet_per_sec = 0
        self.total_packets = 1
        self.total_ports = 1
        self.duration = 0
        self.packets_per_10s = 0
        self.packet_last = 0

class Packet_info:
    def __init__(self,src,dst,proto,dport):
        self.src = src
        self.dst = dst
        self.proto = proto
        self.dport = dport

class Packet_filter:
    def __init__(self):
        self.proto_table ={1:"ICMP",6:"TCP",17:"UDP",2:"IGMP",41: "IPv6",47: "GRE",50: "ESP",51: "AH",58: "ICMPv6",89: "OSPF", 115: "L2TP",132: "SCTP"}
    def _filtering_packets_attr(self,pkt,pkt_ls,scoring_ls,port_ls,freq_time):
        src = dst = ""
        size = proto = dport = syn = ack =0
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = self.proto_table[int(pkt[IP].proto)]
        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            if int(pkt[IPv6].nh) in self.proto_table:
                proto = self.proto_table[int(pkt[IPv6].nh)]
            else: proto = "Unknow"
        if TCP in pkt:
            dport = pkt[TCP].dport
            ack = 1 if (pkt[TCP].flags & 'A') else 0
        elif UDP in pkt:
            dport = pkt[UDP].dport
            
        info = Packet_info(src,dst,proto,dport)
        arg = Scoring_packet_arg(src,freq_time,ack)
        return proto,self.insert_pkt(pkt_ls,scoring_ls,port_ls,info,arg)

    def insert_pkt(self,pkt_ls,scoring_ls,port_ls,info,arg):
        if info.src not in pkt_ls:
            pkt_ls.update({info.src:info})
            scoring_ls.update({info.src:arg})
            with open("/home/ramu/venv-env/ids_mini/traceroute_map/ip_list.txt","a") as file:
                file.write(info.src + "\n")
        else: 
            pkt_ls[info.src] = info
            scoring_ls[info.src].total_packets += 1
            scoring_ls[info.src].ack_raito += arg.ack_raito
            if scoring_ls[info.src].total_packets > 1: scoring_ls[info.src].duration += arg.get_time-scoring_ls[info.src].last_time
            scoring_ls[info.src].last_time = arg.get_time
            if arg.freq > 1: scoring_ls[info.src].packet_per_sec = scoring_ls[info.src].total_packets/arg.freq
            if info.dport not in port_ls[info.src]:
                port_ls[info.src].append(info.dport)
                scoring_ls[info.src].total_ports += 1
        return {"src":info.src,"dst":info.dst,"dport":info.dport,"protocol":info.proto}
