from collections import defaultdict
class Score:
    def __init__(self):
        self.scoring_board = {}
        self.packet_lists = {}
        self.packets_per_10s = {}
        self.total_ports_board = defaultdict(list)
        