#!/usr/bin/env python3

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


class YARA:
    def __init__(self):
        self._rules = ""
        self._matches = []

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

        for k,stream in stream_dict.items():
            payload = extract_payload(stream)
            matches = self._rules.match(data=payload)

        # pcap matching
#        matches = self._rules.match("./out3.pcap")

        if matches:
            logger.info(matches)
            print(matches)

        

if __name__ == "__main__":
#    RULES_DIR = "."+RULES_DIR
#    CAP_PATH = "."+CAP_PATH

    pcap = Util.load_cap("testing2")
    stream_dict = find_streams(pcap)
    yar = YARA()
    yar.run(stream_dict)
    


