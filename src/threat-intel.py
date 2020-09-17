#!/usr/bin/env python3

import glob

class threat_intel:
    def __init__(self):
        self.intel_files = [fname for fname in glob.iglob("../threat_intel/**/*.txt", recursive=True)] 
        self.threat_ips = []
        self.threat_domains = []

    def run(self):
        pass

    def update(self):
        for fname in self.intel_files:
            if "domain" in fname.split("_")[2]:
                with open(fname, 'r') as f:
                    self.threat_domains = [line.strip() for line in f.readlines() if line[0] not in "#"]
            elif "ip" in fname.split("_")[2]:
                with open(fname, 'r') as f:
                    self.threat_ips = [line.strip() for line in f.readlines()]

if __name__ == "__main__":
    threat = threat_intel()
    threat.update()
    #threat.run()
