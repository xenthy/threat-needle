#!/usr/bin/env python3

import os
import glob
import yara
from config import RULES_DIR, CAP_PATH


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

    def run(self):
        self.load_rules()

        # pcap matching
#        matches = self._rules.match("./out3.pcap")
        matches = self._rules.match(CAP_PATH+"sniffed.cap")


        if matches:
            print(matches)
            exit(1)

        

if __name__ == "__main__":
    RULES_DIR = "."+RULES_DIR
    CAP_PATH = "."+CAP_PATH
    yar = YARA()
    yar.run()
    


