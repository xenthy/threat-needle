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
        self.any_condition = "any of them"
        self.__condition = ""

    """
    Define the new rule's Name and Tag
    """
    def new_rule(self, name, tag):
        self.__name = name
        self.__tag = tag
    
    """
    Specify the metadata content (like a readme for different yara rules)
    - key: "author" AND "purpose" 
    """
    def add_meta(self, value, key):
        if key == "author":
            self.__meta["author"] = value
        elif key == "purpose":
            self.__meta["purpose"] = value
        else:
            return -1

    """
    Adding the matching variables into the new rule template created
    - strings: matching variable's value
    - identifier: matching variable's name
    """
    def add_strings(self, strings, identifier):
        self.__strings[identifier] = strings

    """
    Specifying the conditions to the matching variables 
    e.g. "any of them"
    """
    def add_condition(self, condition):
        self.__condition = condition

    """
    Generation of the new yara rule based on the parameters and configurations speicified using functions:
    - new_rule(name, tag)
    - add_meta(value, key)
    - add_strings(strings, identifier)
    - add_condition(condition)
    """
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
    
    # # For GUI adding of rules
    # def append(self):
        # pass

    """
    Build the rule with valid syntax based on the threat intel folder's IP and Domains specified, to be loading by yara in another function
    - Malicious IP: filename naming convention of  xxx_ipX.yar
    - Malicious Domain: filename naming convention of  xxx_domainX.yar
    """
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
        else:
            return -1
        
class Rule:
    """
    Loads in yara rules files (.yar)
    - Errors on invalid syntax during yara rules compilation
    """
    @staticmethod
    def load_rules():
        rule_files = Rule.prepare_rules()
        # Compile all rules file in specified paths
        try:
            rules = yara.compile(filepaths=rule_files)
            logger.info("Threat Intel rules Loaded successfully")
            return rules
        except Exception as e:
            print(f"Invalid Rule file/syntax error: \n{e}")

    """
    Prepare uncompile yara rules files
    """
    @staticmethod
    def prepare_rules():
        results = {}
        for fname in glob.iglob(INTEL_DIR+"**/*.yar", recursive=True):
            with open(fname, 'r') as f:
                results[os.path.basename(fname)[:-4]] = fname
        return results

    """
    Get the list of yara rules files from the "thread_intel" rules directory
    """
    @staticmethod
    def prepare_lists():
        results = {}
        for fname in glob.iglob(INTEL_DIR+"**/*.txt", recursive=True):
            with open(fname, 'r') as f:
                results[os.path.basename(fname)[:-4]] = fname
        return results

    @staticmethod
    def add_rule(name, tag, author, purpose, lines, category):
        yar = Yara_create()
        yar.new_rule(name, tag)
        yar.add_meta(author, "author")
        yar.add_meta(purpose, "purpose")
        ips = []
        
        for index, line in enumerate(lines):
            identifier = "x"+str(index)
            yar.add_strings(line, identifier)
        
        yar.build_rule(category)

    """
    Function mainly used for threat_intel rules compilation as the Domain and IP lists are longer than the allowed number of matching variables per yara rule file
    - To split up the lists (.txt) files into multiple different chunks before compiling and writing to a new yara rule file per chunk
    """
    @staticmethod
    def chunker(seq, size):
        num = math.ceil(len(seq)/size)
        index = 0
        chunked = []
        for i in range(num):
            chunked.append(seq[index:size])
            index = size
            size = size*2 +1

        return chunked

    """
    Function to add a new Yara rule via the Web GUI 
    """
    @staticmethod
    def create_rule(filename, author, name, tag, desc, string, condition=None):
        yar = Yara_create()
        yar.new_rule(name, tag)
        yar.add_meta(author, "author")
        yar.add_meta(desc, "purpose")

        strings = string.split('\n')
        for s in strings:
            identifier = (s.split("=")[0]).replace("$","")
            string_val = ((s.split("=")[1]).replace("\"","")).strip()

            yar.add_strings(string_val, identifier)

        if condition:
            yar.add_condition(condition)
            
        content = yar.generate()
        with open(CUSTOM_RULES_DIR+filename+".yar", 'a+') as f:
            f.write(content)


if __name__ == "__main__":
    # Whole chunk below is for threat_intel.py (OLD, to be deleted before submission)
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
