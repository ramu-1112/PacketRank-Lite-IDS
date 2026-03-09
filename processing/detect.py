from scapy.all import IP,TCP,sniff

class Scoring_packet_arg:
    def __init__(self,packet_size,syn_raito,ack_raito):
        self.packet_size = packet_size
        self.syn_raito = syn_raito
        self.ack_raito = ack_raito
        self.total_ports = 1

class Packet_info:
    def __init__(self,src,dst,proto,dport):
        self.src = src
        self.dst = dst
        self.proto = proto
        self.dport = dport

class Packet_filter:
    def _filtering_packets_attr(self,pkt,pkt_ls,scoring_ls,port_ls):
        src = dst = ""
        size = proto = dport = syn = ack =0
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            size = pkt[IP].len - pkt[IP].ihl*4
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            syn = 1 if (pkt[TCP].flags & 'S') else 0
            ack = 1 if (pkt[TCP].flags & 'A') else 0

        info = Packet_info(src,dst,proto,dport)
        arg = Scoring_packet_arg(size,syn,ack)
        return self.insert_pkt(pkt_ls,scoring_ls,port_ls,info,arg)

    def insert_pkt(self,pkt_ls,scoring_ls,port_ls,info,arg):
        if info.src not in pkt_ls:
            pkt_ls.update({info.src:info})
            scoring_ls.update({info.src:arg})
        else: 
            pkt_ls[info.src] = info
            scoring_ls[info.src].syn_raito += arg.syn_raito
            scoring_ls[info.src].ack_raito += arg.ack_raito
            if info.dport not in port_ls[info.src]:
                port_ls[info.src].append(info.dport)
                scoring_ls[info.src].total_ports += 1
        return info.src        
