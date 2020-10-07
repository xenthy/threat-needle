#!/usr/bin/env python3

''' 
    Need to make a separation of UDP and TCP searching, loading 2 different set of rules
'''

import os
import glob
import yara
from util import Util
from config import RULES_DIR, CAP_PATH
from features import find_streams, extract_payload
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
        self._matches = []
        self.flagged = {}

    # Loads in uncompiled rules files
    def load_rules(self):
        rule_files = self._prepare_rules(RULES_DIR)
        # Compile all rules file in specified paths
        try:
            self._rules = yara.compile(filepaths=rule_files)
        except Exception as e:
            print(f"Invalid Rule file/syntax error: \n{e}")

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
            payload = extract_payload(stream)
            matches = self._rules.match(data=payload)

            if matches:
                logger.info(f"{k} --> {matches}")

                # Need to make a separation of UDP and TCP searching, loading 2 different set of rules
                self.flagged[k] = dict(matches = payload)

    # Returns a dictionary of lists
    def get_flagged(self):
        return self.flagged

if __name__ == "__main__":
    #    RULES_DIR = "."+RULES_DIR
    #    CAP_PATH = "."+CAP_PATH

    pcap = Util.load_cap("testing2")
    stream_dict = find_streams(pcap)
    yar = Yara()
    yar.run(stream_dict)
