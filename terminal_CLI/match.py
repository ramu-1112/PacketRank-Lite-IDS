import re, ipaddress

class PreProcessing:
    def __init__(self):
        self.func = ["open","blockv4","unblockv4","blockv6","unblockv6"]
        self.own_func = ["help","showrulev4","showrulev6","start","stop"]

    def checkIPv4(self,text):
        rule_IPv4 = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        match = re.search(rule_IPv4,text)
        if match: return text[match.start():match.end()]

    def checkPort(self,text):
        rule_Port = r"\s(\d{1,5})$"
        match = re.search(rule_Port,text)
        if match: return text[match.start():match.end()]
    
    def checkIPv6(self, text):
        rule_IPv6 = r"\b([0-9a-fA-F]{0,4}:){4,7}([0-9a-fA-F]{0,4})"
        match = re.search(rule_IPv6,text)
        if match: return text[match.start():match.end()]

    def matching(self,text):
        arr = text.split()
        try:typ = arr[0]
        except Exception as e:
            print("NO command invalid from match")
            pass
        if typ in self.func:
            if self.checkIPv4(text): return typ,self.checkIPv4(text)
            if self.checkPort(text): return typ,self.checkPort(text)
            if self.checkIPv6(text): return typ,self.checkIPv6(text)
            return None, None
        elif typ in self.own_func:
            return typ,None
        else:return None,None


