#!/usr/bin/env python3

import os
import glob
import yara


class YARA:
    def __init__(self):
        self._rules_path = ""
        self._rules = ""
        self._matches = []

    # Loads in uncompiled rules files
    def load_rules(self):
        rule_files = self._prepare_rules(self._rules_path)
        
        # Compile all rules file in specified paths
        try:
            self._rules = yara.compile(filepaths=rule_files)
        except Exception as e:
            print(f"Invalid Rule file/syntax error: \n{e}")

    # Prepare uncompile yara rules files
    def _prepare_rules(self, rules):
        results = {}
        for fname in glob.iglob(rules+"**/*.yar", recursive=True):
            with open(fname, 'r') as f:
                results[os.path.basename(fname)[:-4]] = fname 
        return results

    def run(self, rules_path):
        self._rules_path = rules_path
        self.load_rules()

        # pcap matching
#        matches = self._rules.match("./out3.pcap")
        matches = self._rules.match("./testinlol")


        if matches:
            print(matches)
            exit(1)

        

if __name__ == "__main__":
    yar = YARA()
    yar.run("/root/Desktop/ICT2202_IOC/rules/")
    


