#!/usr/bin/env python3

'''
Incomplete, thinking of implementing a convertor to yara instead, then use yara to run the whole search, with segmented parts for each different 'protocol'
'''

import re
import glob
from util import Util
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
        self.threat_list = {}

    def run(self, temp_plist):
        for packet in temp_plist:
            extracted = self.extract_ip_domains(packet)
            if extracted:
                self.hunt_threat(extracted, packet)

    def extract_ip_domains(self, packet):
        extracted = []

        parsed_pkt = Util.convert_packet(packet)
        if "HTTPRequest" in parsed_pkt:
            extracted.append(parsed_pkt['HTTPRequest']['Host'])
            # extracted.append(parsed_pkt['HTTPRequest']['Path'])  # URI

        if "DNSQR" in parsed_pkt:
            extracted.append(parsed_pkt['DNSQR']['qname'])

        if "IP" in parsed_pkt:
            extracted.append(parsed_pkt['IP']['src'])
            extracted.append(parsed_pkt['IP']['dst'])

        return extracted

    def hunt_threat(self, found, packet):
        for threat in found:
            if (matches := self.rules.match(data=threat)):
                if threat not in self.threat_list:
                    self.threat_list[threat] = [packet]
                    org.add_packet_entry(threat, packet, matches)
                else:
                    self.threat_list[threat] = self.threat_list[threat] + [packet]

    def threat_update(self):
        rule = Rule()
        filenames = rule.prepare_lists()
        entries = {"domains": [], "ips": []}
        for filename in filenames:
            identify = filename.split("_")[1]
            with open(INTEL_DIR+filename+".txt", 'r') as f:
                lines = [line.strip() for line in f.readlines() if "#" not in line if line.strip() != ""]

            if "domain" == identify:
                entries["domains"] += lines
            elif "ip" == identify:
                entries["ips"] += lines

        for entry, lines in entries.items():
            chunked = rule.chunker(lines, 9999)
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
