import re

class PreProcessing:
    def __init__(self):
        self.func = ["open","block","unblock"]
        self.own_func = ["help","showrule"]

    def checkIP(self,text):
        rule_IP = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        match = re.search(rule_IP,text)
        if match: return text[match.start():match.end()]

    def checkPort(self,text):
        rule_Port = r"\s(\d{1,5})$"
        match = re.search(rule_Port,text)
        if match: return text[match.start():match.end()]

    def matching(self,text):
        arr = text.split()
        try:typ = arr[0]
        except Exception as e:
            print("NO command invalid from match")
            pass
        if typ in self.func:
            if self.checkIP(text): return typ,self.checkIP(text)
            if self.checkPort(text): return typ,self.checkPort(text)
            return None, None
        elif typ in self.own_func:
            return typ,None
        else:return None,None


