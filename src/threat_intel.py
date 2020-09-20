#!/usr/bin/env python3

'''
Incomplete, thinking of implementing a convertor to yara instead, then use yara to run the whole search, with segmented parts for each different 'protocol'
'''

import glob
from util import Util
from pprint import pformat
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
        self.intel_files = [fname for fname in glob.iglob(INTEL_DIR+"**/*.txt", recursive=True)]
        self.threat_ips = set()
        self.threat_domains = set()

    def run(self):
        self.update()
        pcap = Util.load_cap("sniffed")
        stream_dict = find_streams(pcap)

        for k, stream in stream_dict.items():
            # self.search(k)
            print(stream)
            exit(1)

    def search(self, string):
        for ip in self.threat_ips:
            if ip in string:
                print(ip)

    def update(self):
        for fname in self.intel_files:
            if "domain" in fname.split("_")[2]:
                with open(fname, 'r') as f:
                    temp = [line.strip() for line in f.readlines() if line[0] not in "#"]
                    self.threat_domains.update(temp)

            elif "ip" in fname.split("_")[2]:
                with open(fname, 'r') as f:
                    temp = [line.strip() for line in f.readlines()]
                    self.threat_ips.update(temp)


if __name__ == "__main__":
    INTEL_DIR = "."+INTEL_DIR
    threat = ThreatIntel()
    # threat.update()
    threat.run()
