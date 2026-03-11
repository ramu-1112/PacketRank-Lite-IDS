from .match import PreProcessing

preprocessing = PreProcessing()

class RuleManagement:
    def __init__(self):
        self.rule_dictv4 = {}
        self.rule_setv4 = set()
        self.rule_dictv6 = {}
        self.rule_setv6 = set()
        self.rule_command_change = ["blockv4","unblockv4","blockv6","unblockv6"]
    
    def reset_index_rulev4(self):
        self.rule_dictv4 = {i: v for i, v in enumerate(self.rule_dictv4.values(),start=1)}
        return
    def reset_index_rulev6(self):
        self.rule_dictv6 = {i: v for i, v in enumerate(self.rule_dictv6.values(),start=1)}
        return
    def check_rule_in_dictv4(self,text):
        typ,ip_port = preprocessing.matching(text)
        print(ip_port)
        if typ in self.rule_command_change:
            if typ == "unblockv4": return ip_port
            if ip_port not in self.rule_setv4: return ip_port
            else: return False

    def check_rule_in_dictv6(self,text):
        typ,ip_port = preprocessing.matching(text)
        print(ip_port)
        if typ in self.rule_command_change:
            if typ == "unblockv6": return ip_port
            if ip_port not in self.rule_setv6: return ip_port
            else: return False

    def insert_rulev4(self,text):
        ip_port = self.check_rule_in_dictv4(text)
        if ip_port: 
            self.rule_dictv4.update({len(self.rule_setv4)+1:ip_port})
            self.rule_setv4.add(ip_port)
            return "success",f"Insert sucessfully {ip_port}!"
        else: return "info", f"{ip_port} has in the chain rule"
    
    def insert_rulev6(self,text):
        ip_port = self.check_rule_in_dictv6(text)
        if ip_port: 
            self.rule_dictv6.update({len(self.rule_setv6)+1:ip_port})
            self.rule_setv6.add(ip_port)
            return "success",f"Insert sucessfully {ip_port}!"
        else: return "info", f"{ip_port} has in the chain rule"

    def erase_rulev4(self,id):
        rule_id = int(id)
        if rule_id in self.rule_dictv4:
            self.rule_setv4.discard(self.rule_dictv4[rule_id])
            self.rule_dictv4.pop(rule_id)
            self.reset_index_rulev4()
            return "success",f"Unblock successfully rule {rule_id}!"
        else: return "error",f"Rule {rule_id} is not in rule list, Please type rule has in the rule list !!"
    def erase_rulev6(self,id):
        rule_id = int(id)
        if rule_id in self.rule_dictv6:
            self.rule_setv6.discard(self.rule_dictv6[rule_id])
            self.rule_dictv6.pop(rule_id)
            self.reset_index_rulev6()
            return "success",f"Unblock successfully rule {rule_id}!"
        else: return "error",f"Rule {rule_id} is not in rule list, Please type rule has in the rule list !!"