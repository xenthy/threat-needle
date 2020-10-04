#!/usr/bin/env python3

'''
Incomplete, thinking of implementing a convertor to yara instead, then use yara to run the whole search, with segmented parts for each different 'protocol'
'''

import glob
from util import Util
from yara_create import *
from config import INTEL_DIR
from features import extract_payload, find_streams
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class ThreatIntel:
    def __init__(self):
        self.rules = ""

    def run(self, temp_plist):
        #self.threat_update()
        for packet in temp_plist:
            logger.info(packet)
    
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


if __name__ == "__main__":
    threat = ThreatIntel()
    threat.run()
