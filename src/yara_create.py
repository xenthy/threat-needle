#!/usr/bin/env python3

'''
(yeet todo)
After threat_intel runs ok
- add condition functions
- organize and optimize dem codes properly
'''

import os
import glob
import math
import yara
from config import INTEL_DIR
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

class Yara_create:
    def __init__(self):
        self.__name = ""
        self.__meta = {"author":"someone","purpose":"something"}
        self.__strings = dict()
        self.__condition = "\n\tcondition:\n\t\tany of them"

    def new_rule(self, name):
        self.__name = name
    
    def add_meta(self, value, key):
        if key == "author":
            self.__meta["author"] = value
        elif key == "purpose":
            self.__meta["purpose"] = value
        else:
            return -1

    '''
    Not implementing condition as of yet, after finish threat_intel.py working, then implement condition for web UI adding rules
    '''
    def add_strings(self, strings, identifier, condition=None):
        self.__strings[identifier] = strings
        self.__condition = condition

    def generate(self):
        head = f"rule {self.__name}\n{{"
        meta = f"\n\tmeta:\n\t\tauthor = \"{self.__meta['author']}\"\n\t\tpurpose = \"{self.__meta['purpose']}\""
        strings = f"\n\n\tstrings:"
        for k, v in self.__strings.items():
           strings += f"\n\t\t${k} = \"{v}\""

        tail = "\n}"
        
        return head+meta+strings+"\n"+self.__condition+tail
    
    # For GUI adding of rules
    def append(self):
        pass

    def build_rule(self, temp_category):
        category = temp_category.split("_")[0]
        if category in ("domains", "ips"):
            content = self.generate()
            filename = INTEL_DIR+temp_category+".yar"

            # Clear file IF it exists
            try:
                open(filename, 'w').close()
            except:
                pass
                
            with open(filename, 'a+') as f:
                f.write(content)
            

            #logger.info("Threat Intel rules created")
        else:
            return -1
        
class Rule:
    def __init__(self):
        self.rules = ""
    # Loads in uncompiled rules files
    def load_rules(self):
        rule_files = self.prepare_rules()
        # Compile all rules file in specified paths
        try:
            self.rules = yara.compile(filepaths=rule_files)
            logger.info("Threat Intel rules Loaded successfully")
            return self.rules
        except Exception as e:
            print(f"Invalid Rule file/syntax error: \n{e}")

    # Prepare uncompile yara rules files
    def prepare_rules(self):
        results = {}
        for fname in glob.iglob(INTEL_DIR+"**/*.yar", recursive=True):
            with open(fname, 'r') as f:
                results[os.path.basename(fname)[:-4]] = fname
        return results

    # Prepare uncompile yara rules files
    def prepare_lists(self):
        results = {}
        for fname in glob.iglob(INTEL_DIR+"**/*.txt", recursive=True):
            with open(fname, 'r') as f:
                results[os.path.basename(fname)[:-4]] = fname
        return results

    def add_rule(self, name, author, purpose, lines, category):
        yar = Yara_create()
        yar.new_rule(name)
        yar.add_meta(author, "author")
        yar.add_meta(purpose, "purpose")
        ips = []
        
        for index, line in enumerate(lines):
            identifier = "x"+str(index)
            yar.add_strings(line, identifier)
        
        yar.build_rule(category)

    def chunker(self, seq, size):
        num = math.ceil(len(seq)/size)
        index = 0
        chunked = []
        for i in range(num):
            chunked.append(seq[index:size])
            index = size
            size = size*2 +1

        return chunked

if __name__ == "__main__":
    # Whole chunk below is for threat_intel.py
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

    rule.load_rules()