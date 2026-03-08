from .match import PreProcessing

preprocessing = PreProcessing()

class RuleManagement:
    def __init__(self):
        self.rule_dict = {}
        self.rule_set = set()
        self.rule_command_change = ["block","unblock"]
    
    def reset_index_rule(self):
        self.rule_dict = {i: v for i, v in enumerate(self.rule_dict.values())}
        return
    
    def check_rule_in_dict(self,text):
        typ,ip_port = preprocessing.matching(text)
        print(ip_port)
        if typ in self.rule_command_change:
            if typ == "unblock": return ip_port
            if ip_port not in self.rule_set: return ip_port
            else: return False

    def insert_rule(self,text):
        ip_port = self.check_rule_in_dict(text)
        if ip_port: 
            self.rule_dict.update({len(self.rule_set):ip_port})
            self.rule_set.add(ip_port)
            return "success",f"Insert sucessfully {ip_port}!"
        else: return "info", f"{ip_port} has in the chain rule"

    def erase_rule(self,id):
        rule_id = int(id)
        if rule_id in self.rule_dict:
            self.rule_set.discard(self.rule_dict[rule_id])
            self.rule_dict.pop(rule_id)
            self.reset_index_rule()
            return "success",f"Unblock successfully rule {rule_id}!"
        else: return "error",f"Rule {rule_id} is not in rule list, Please type rule has in the rule list !!"