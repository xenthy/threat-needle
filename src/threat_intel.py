#!/usr/bin/env python3

'''
Incomplete, thinking of implementing a convertor to yara instead, then use yara to run the whole search, with segmented parts for each different 'protocol'
'''

import re
import glob
from util import Util
from scapy.all import IP
from scapy.layers import http
from yara_create import *
from config import INTEL_DIR
from flagged_organize import Organize
from features import extract_payload, find_streams
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
org = Organize()

class ThreatIntel:
    def __init__(self):
        self.rules = ""
        self.threat_list = []

    def run(self, temp_plist):
        for packet in temp_plist:
#            if packet.haslayer(http.HTTPRequest):
#                http_layer = packet.getlayer(http.HTTPRequest)
#                ip_layer = packet.getlayer(IP)
#                print(f"{ip_layer.fields} - {http_layer.fields}")

            found = self.extract_ip_domains(bytes(packet).decode(errors="backslashreplace"))
            if found:
                self.hunt_threat(found, packet) 

    def extract_ip_domains(self, packet):
        ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}', packet)
        url_regex = re.compile('((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)', re.DOTALL)
        domains = re.findall(url_regex,packet)
        domains = [domain[0] for domain in domains]
        found = ips + domains
        return found
    
    def hunt_threat(self, found, packet):
        for threat in found:
            matches = self.rules.match(data=threat)
            if matches:
                logger.info(f"{threat} --> {matches}")
                self.threat_list.append(packet)
                org.add_packet_entry(threat, packet, matches)

    def threat_update(self):
        rule = Rule()
        filenames = rule.prepare_lists()
        entries = {"domains":[],"ips":[]}
        for filename in filenames:
            identify = filename.split("_")[1]
            with open(INTEL_DIR+filename+".txt",'r') as f:
                lines = [line.strip() for line in f.readlines() if "#" not in line if line.strip() != ""]

            if "domain" == identify:
                entries["domains"]+= lines
            elif "ip" == identify:
                entries["ips"]+= lines

        for entry, lines in entries.items():
            chunked = rule.chunker(lines,9999)
            for index, chunk in enumerate(chunked):
                name = entry+str(index)
                author = "Auto Generated"
                purpose = "Threat Intel Domains/IPs"
                if "domains" == entry:
                    category = "domains_"+str(index)
                elif "ips" == entry:
                    category = "ips_"+str(index)

                rule.add_rule(name, author, purpose, chunk, category)

        self.rules = rule.load_rules()

    '''
    May can implement another database to write to instead
    - mysql
    - postgresql
    '''
    def get_threats(self):
        if self.threat_list:
            return self.threat_list

if __name__ == "__main__":
    threat = ThreatIntel()
    threat.run()
