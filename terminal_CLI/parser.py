from .match import PreProcessing

preprocessing = PreProcessing()

class Parser:
    def __init__(self):
        self.mapping = {"s":"-s","p":"-p","port":"--dport"}
        self.command_CLI_head = {"open":"ncat -l ","block":"/sbin/iptables -A INPUT ","unblock":"/sbin/iptables -D INPUT "}
        self.command_CLI_tail = {"block":"-j DROP","unblock":""}
        self.command_own = {"help":"","showrule":"","start":"","stop":""}

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