#!/usr/bin/env python3

''' 
    Need to make a separation of UDP and TCP searching, loading 2 different set of rules
'''

import os
import glob
import yara
import datetime
from util import Util
from escapy import Escapy
from flagged_organize import Organize
from config import RULES_DIR, CAP_PATH, INTEL_DIR
from features import find_streams, extract_payload
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
org = Organize()


class Yara:
    def __init__(self):
        self._rules = ""
        self._url_rules = ""
        self._matches = []
        self.udp_ports = ["53", "80", "443"]

    # Loads in uncompiled rules files
    def load_rules(self):
        rule_files = self._prepare_rules(RULES_DIR)
        url_rule_files = self._prepare_rules(INTEL_DIR)
        # Compile all rules file in specified paths
        try:
            self._rules = yara.compile(filepaths=rule_files)
            self._url_rules = yara.compile(filepaths=url_rule_files)
        except Exception as e:
            logger.error(f"Invalid Rule file/syntax error: \n{e}")
            #print(f"Invalid Rule file/syntax error: \n{e}")

    # Prepare uncompile yara rules files
    def _prepare_rules(self, rules):
        results = {}
        for fname in glob.iglob(RULES_DIR+"**/*.yar", recursive=True):
            with open(fname, 'r') as f:
                results[os.path.basename(fname)[:-4]] = fname
        return results

    def run(self, stream_dict):
        self.load_rules()
        matches = None

        for k, stream in stream_dict.items():
            if (payload := extract_payload(stream)) is None:
                continue
            if (matches := self._rules.match(data=payload)):

                # NOT TESTED YET so commented out
                if "url" in matches[0].rule:
                    self.url_yar(k, matches)

                # Need to make a separation of UDP and TCP searching, loading 2 different set of rules
                org.add_stream_entry(k, payload, matches)

    '''
    function "url_yar(self, k, matches)" NOT TESTED YET

    E.g. 
    When there is a URL in an email (or in any stream payload), it will search through the "suspicious" or "malicious" urls/ips specified in threat_intel's yara rules, if matched, flag it

    '''

    def url_yar(self, k, matches):
        for url in matches[0].strings:
            if (matches := self._url_rules.match(data=url[2])):
                raw_timestamp = Escapy.convert_packet(k, "Timestamp")
                timestamp = str(datetime.datetime.utcfromtimestamp(raw_timestamp))
                print(f'in url_yar: {matches[0].strings}')
                org.add_packet_entry(url[2], k, matches, timestamp)


if __name__ == "__main__":
    #    RULES_DIR = "."+RULES_DIR
    #    CAP_PATH = "."+CAP_PATH

    pcap = Util.load_cap("testing2")
    stream_dict = find_streams(pcap)
    yar = Yara()
    yar.run(stream_dict)
