#!/usr/bin/env python3

''' 
    Need to make a separation of UDP and TCP searching, loading 2 different set of rules
'''

from util import Util
from escapy import Escapy
from thread import Thread
from organize import Organize
from config import RULES_DIR, CAP_PATH, INTEL_DIR
from features import find_streams, extract_payload

import os
import glob
import yara
import datetime

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


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
            logger.error(f"Invalid Rule file/syntax error: \n{e} [{Thread.name()}]")
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
            if (payload := extract_payload(stream)) is not None:
                try:
                    if (matches := self._rules.match(data=payload)):
                        raw_timestamp = Escapy.convert_packet(stream[0], "Timestamp")
                        timestamp = str(datetime.datetime.utcfromtimestamp(raw_timestamp))

                        if "url" in matches[0].rule:
                            self.url_yar(stream, k, payload, matches, timestamp)

                        Organize.add_stream_entry(k, stream, payload, matches, timestamp)
                except AttributeError:
                    logger.critical(f"Yara rules error, check rules in \"rules/custom_rules/<file>\" [{Thread.name()}]")

    '''
    function "url_yar(self, stream, k, matches)" 

    E.g. 
    When there is a URL in an email (or in any stream payload), it will search through the "suspicious" or "malicious" urls/ips specified in threat_intel's yara rules, if matched, flag it

    '''

    def url_yar(self, stream, k, payload, matches, timestamp):
        for url in matches[0].strings:
            if (matches := self._url_rules.match(data=url[2])):
                Organize.add_stream_entry(k, stream, payload, matches, timestamp)


if __name__ == "__main__":
    #    RULES_DIR = "."+RULES_DIR
    #    CAP_PATH = "."+CAP_PATH

    pcap = Util.load_cap("testing2")
    stream_dict = find_streams(pcap)
    yar = Yara()
    yar.run(stream_dict)
