from .parser import Parser
from .check_rule import RuleManagement
from processing.capture_pac import * 
import subprocess

rulemanagement = RuleManagement()
parser = Parser()
sniff_cmd = None

class CommandTable:
    def __init__(self):
        self.table = {"block":self.block_cmdCLI,"unblock":self.unblock_cmdCLI,"open":""}
        self.table_ownCLI = {"help":self.help_cmdCLI,"showrule":self.showrule_cmdCLI}
        self.table_threadCLI = {"start":self.start_sniff_cmdCLI,"stop":self.stop_sniff_cmdCLI}
    def exec_command(self,text,func):
        typ,command = parser.command_parser(text)
        if typ in self.table and command is not None:
                if subprocess.run(command.split()).returncode == 0: return self.table[typ](text)
        elif typ in self.table_ownCLI:
            return self.table_ownCLI[typ]()
        elif typ in self.table_threadCLI:
            return self.table_threadCLI[typ](func)
        else: return "error", "Command does not exists, Please look up command again!"

    def showrule_cmdCLI(self):
        rule_ls = ""
        for key,value in rulemanagement.rule_dict.items():
            rule_ls += f"[{key}] {value} <br>"
        return "info", rule_ls
        
    def help_cmdCLI(self):
        text = """
        [+]How to use this tool, type command allow following structure:<br>
        [+]Open ports: open [port]<br>
        [+]Block from IP,port: block s [IP] / p [packet_name] [port] <br>"""
        return "info",text

    def block_cmdCLI(self,text):
        return rulemanagement.insert_rule(text)
    
    def unblock_cmdCLI(self,text):
        idx = rulemanagement.check_rule_in_dict(text)
        return rulemanagement.erase_rule(idx)
    
    def start_sniff_cmdCLI(self,func):
        global sniff_cmd
        sniff_cmd = SniffPacket()
        sniff_cmd.packet_captured_signal.connect(func)
        sniff_cmd.start()
        return "success","Capturing...."
    
    def stop_sniff_cmdCLI(self,func):
        global sniff_cmd
        if sniff_cmd is not None:
            sniff_cmd.stop()
            sniff_cmd = None
        return "success","Done"
