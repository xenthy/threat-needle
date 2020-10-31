import os
import glob
import math
import yara
from config import INTEL_DIR, CUSTOM_RULES_DIR, MAL_DIR
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP, LOG_LEVEL
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class YaraCreate:
    """Yara_create

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
    """

    def __init__(self):
        self.__name = ""
        self.__tag = ""
        self.__meta = {"author": "someone", "purpose": "something"}
        self.__strings = dict()
        self.any_condition = "any of them"
        self.__condition = ""

    def new_rule(self, name, tag):
        """
        Define the new rule's Name and Tag
        """
        self.__name = name
        self.__tag = tag

    def add_meta(self, value, key):
        """
        Specify the metadata content (like a readme for different yara rules)
        - key: "author" AND "purpose"
        """
        if key == "author":
            self.__meta["author"] = value
        elif key == "purpose":
            self.__meta["purpose"] = value

    def add_strings(self, strings, identifier):
        """
        Adding the matching variables into the new rule template created
        - strings: matching variable's value
        - identifier: matching variable's name
        """
        self.__strings[identifier] = strings

    def add_condition(self, condition):
        """
        Specifying the conditions to the matching variables
        e.g. "any of them"
        """
        self.__condition = condition

    def generate(self):
        """
        Generation of the new yara rule based on the parameters and configurations speicified using functions:
        - new_rule(name, tag)
        - add_meta(value, key)
        - add_strings(strings, identifier)
        - add_condition(condition)
        """
        head = f"rule {self.__name} : {self.__tag}\n{{"
        meta = f"\n\tmeta:\n\t\tauthor = \"{self.__meta['author']}\"\n\t\tpurpose = \"{self.__meta['purpose']}\""
        strings = "\n\n\tstrings:"
        for k, v in self.__strings.items():
            if "{" in v[0] and "}" in v[-1]:
                strings += f"\n\t\t${k} = {v}"
            else:
                strings += f"\n\t\t${k} = \"{v}\""

        if not self.__condition:
            self.__condition = self.any_condition

        cond_format = "\n\tcondition:\n\t\t"
#
        tail = "\n}"

        return head+meta+strings+"\n"+cond_format+self.__condition+tail

    def build_rule(self, temp_category):
        """
        Build the rule with valid syntax based on the threat intel folder's IP and Domains specified, 
        to be loading by yara in another function
        - Malicious IP: filename naming convention of  xxx_ipX.yar
        - Malicious Domain: filename naming convention of  xxx_domainX.yar
        """
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


class Rule:
    @staticmethod
    def load_rules():
        """
        Loads in yara rules files (.yar)
        - Errors on invalid syntax during yara rules compilation
        """
        rule_files = Rule.prepare_rules(INTEL_DIR)
        # Compile all rules file in specified paths
        try:
            rules = yara.compile(filepaths=rule_files)
            logger.info("Threat Intel rules Loaded successfully")
            return rules
        except Exception as error:
            print(f"Invalid Rule file/syntax error: \n{error}")

    @staticmethod
    def prepare_rules(rules_directory):
        """
        Prepare uncompile yara rules files
        """
        results = {}
        for fname in glob.iglob(rules_directory+"**/*.yar", recursive=True):
            if os.path.isfile(fname):
                results[os.path.basename(fname)[:-4]] = fname
        return results

    @staticmethod
    def prepare_lists():
        """
        Get the list of yara rules files from the "thread_intel" rules directory
        """
        results = {}
        for fname in glob.iglob(INTEL_DIR+"**/*.txt", recursive=True):
            if os.path.isfile(fname):
                results[os.path.basename(fname)[:-4]] = fname
        return results

    @staticmethod
    def add_rule(name, tag, author, purpose, lines, category):
        yar = YaraCreate()
        yar.new_rule(name, tag)
        yar.add_meta(author, "author")
        yar.add_meta(purpose, "purpose")

        for index, line in enumerate(lines):
            identifier = "x"+str(index)
            yar.add_strings(line, identifier)

        yar.build_rule(category)

    @staticmethod
    def chunker(seq, size):
        """
        Function mainly used for threat_intel rules compilation 
        as the Domain and IP lists are longer than the allowed number of matching variables per yara rule file
        - To split up the lists (.txt) files into multiple different chunks 
            before compiling and writing to a new yara rule file per chunk
        """
        num = math.ceil(len(seq)/size)
        index = 0
        chunked = []
        for _ in range(num):
            chunked.append(seq[index:size])
            index = size
            size = size*2 + 1

        return chunked

    @staticmethod
    def create_rule(filename, author, name, tag, desc, string, condition=None):
        """
        Function to add a new Yara rule via the Web GUI 
        """
        yar = YaraCreate()
        yar.new_rule(name, tag)
        yar.add_meta(author, "author")
        yar.add_meta(desc, "purpose")

        strings = string.split('\n')
        for string in strings:
            identifier = (string.split("=")[0]).replace("$", "")
            string_val = ((string.split("=")[1]).replace("\"", "")).strip()

            yar.add_strings(string_val, identifier)

        if condition:
            yar.add_condition(condition)

        content = yar.generate()
        with open(CUSTOM_RULES_DIR+filename+".yar", 'a+') as file_obj:
            file_obj.write(content)


class YaraFiles:
    threat_contents = {}
    mal_contents = {}
    custom_contents = {}

    @staticmethod
    def get_threat_rules():
        files = Rule.prepare_rules(INTEL_DIR) 
        for filename, filepath in files.items():
            with open(filepath, 'r') as f:
                YaraFiles.threat_contents[filename+".yar"] = f.read()
        return YaraFiles.threat_contents

    @staticmethod
    def get_mal_rules():
        files = Rule.prepare_rules(MAL_DIR) 
        for filename, filepath in files.items():
            with open(filepath, 'r') as f:
                YaraFiles.mal_contents[filename+".yar"] = f.read()
        return YaraFiles.mal_contents
    
    @staticmethod
    def get_custom_rules():
        files = Rule.prepare_rules(CUSTOM_RULES_DIR) 
        for filename, filepath in files.items():
            with open(filepath, 'r') as f:
                YaraFiles.custom_contents[filename+".yar"] = f.read()
        return YaraFiles.custom_contents

    
