from .match import PreProcessing

preprocessing = PreProcessing()

class Parser:
    def __init__(self):
        self.mapping = {"s":"-s","p":"-p","port":"--dport"}
        self.command_CLI_head = {"blockv4":"/sbin/iptables -A INPUT ","unblockv4":"/sbin/iptables -D INPUT ","blockv6":"/sbin/ip6tables -A INPUT ","unblockv6":"/sbin/ip6tables -D INPUT "}
        self.command_CLI_tail = {"blockv4":"-j DROP","unblockv4":"","blockv6":"-j DROP","unblockv6":""}
        self.command_own = {"help":"","showrulev4":"","showrulev6":"","start":"","stop":""}

    def command_parser(self,text):
        arr = text.split()[1:]
        typ,ip_port = preprocessing.matching(text)
        cmdCLI = ""
        if typ in self.command_CLI_head:
            cmdCLI += self.command_CLI_head[typ]
        elif typ in self.command_own:
            return typ,None
        else: return False,None
        
        if ip_port:
            for part in arr:
                if part in self.mapping:
                    cmdCLI += self.mapping[part] +" "
                else: cmdCLI += part + " "
            cmdCLI += self.command_CLI_tail[typ]
            return typ,cmdCLI
        else: return False,None