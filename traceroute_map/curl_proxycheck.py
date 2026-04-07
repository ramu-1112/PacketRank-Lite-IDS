import requests
import os
from dotenv import load_dotenv
from map import map_trace

load_dotenv()
API_KEY = os.getenv("API_KEY")
params = {"key":API_KEY}

class update_marker:
    def __init__(self):
        self.ip_draw = {}
        self.check_ip = {}
    def fetch(self):
        new_ip = {}
        with open("/home/ramu/venv-env/ids_mini/traceroute_map/ip_list.txt","r") as file:
            ip_list = file.readlines()
            for ip in ip_list:
                ip = ip.strip()
                self.check_ip.update({ip:False})
                if ip not in self.ip_draw and self.check_ip[ip] == False:
                    url = f"https://proxycheck.io/v3/{ip}"
                    print(url)
                    response = requests.get(url, params=params)
                    print(response)
                    data = response.json()

                    if data.get("status") == "ok":
                        try:
                            proxy = data.get(ip).get("detections").get("proxy")
                            vpn = data.get(ip).get("detections").get("vpn")
                            tor = data.get(ip).get("detections").get("tor")
                            lat = data.get(ip).get("location").get("latitude")
                            lon = data.get(ip).get("location").get("longitude")
                            provider = data.get(ip).get("network").get("provider")
                            self.check_ip[ip] = True
                            self.ip_draw.update({ip:""})
                            new_ip.update({ip:[proxy,vpn,tor,lat,lon,provider]})
                            print("update done")
                        except Exception as e:
                            pass
                    else: 
                        self.check_ip[ip] = True
                        self.ip_draw.update({ip:""})

        return new_ip