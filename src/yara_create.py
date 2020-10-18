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
from config import INTEL_DIR, CUSTOM_RULES_DIR
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

'''Yara_create

There are 3 defined functions to craft a Yara Rule
- new_rule(rule_name)
- add_meata(value, key)
- add_strings(strings, identifier, condition=None)

E.g Yara Rule

    rule with_attachment {
            meta:
                    author = "Antonio Sanchez <asanchez@hispasec.com>"
                    reference = "http://laboratorio.blogs.hispasec.com/"
                    description = "Rule to detect the presence of an or several attachments"
            strings:
                    $attachment_id = "X-Attachment-Id"
            condition:
                    $attachment_id
    }

E.g. Calling functions to craft yara rule (as per example above)

1. new_rule("without_attachment")
2. add_meata("Ella Vader","author")
3. add_strings("X-Attachment-Id","attachment_id", )

'''
class Yara_create:
    def __init__(self):
        self.__name = ""
        self.__tag = ""
        self.__meta = {"author":"someone","purpose":"something"}
        self.__strings = dict()
        #self.any_condition = "\n\tcondition:\n\t\tany of them"
        self.any_condition = "any of them"
        self.__condition = ""

    def new_rule(self, name, tag):
        self.__name = name
        self.__tag = tag
    
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
    def add_strings(self, strings, identifier):
        self.__strings[identifier] = strings

    def add_condition(self, condition):
        self.__condition = condition

    def generate(self):
        head = f"rule {self.__name} : {self.__tag}\n{{"
        meta = f"\n\tmeta:\n\t\tauthor = \"{self.__meta['author']}\"\n\t\tpurpose = \"{self.__meta['purpose']}\""
        strings = f"\n\n\tstrings:"
        for k, v in self.__strings.items():
           strings += f"\n\t\t${k} = \"{v}\""

        if not self.__condition:
            self.__condition = self.any_condition

        cond_format = "\n\tcondition:\n\t\t"
# 
        tail = "\n}"
        
        return head+meta+strings+"\n"+cond_format+self.__condition+tail
    
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

    def add_rule(self, name, tag, author, purpose, lines, category):
        yar = Yara_create()
        yar.new_rule(name, tag)
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

class Custom_create:
    def custom_yara(author, name, desc, string, condition=None):
        yar = Yara_create()
        yar.new_rule(name.split(":")[0], name.split(":")[1])
        yar.add_meta(author, "author")
        yar.add_meta(desc, "purpose")

        strings = string.split('\n')
        for s in strings:
            identifier = (s.split("=")[0]).replace("$","")
            string_val = (s.split("=")[1]).replace("\"","")

            yar.add_strings(string_val, identifier)

        if condition:
            yar.add_condition(condition)
            
        content = yar.generate()
        with open(CUSTOM_RULES_DIR+"custom1.yar", 'a+') as f:
            f.write(content)


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
