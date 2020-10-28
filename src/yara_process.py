#!/usr/bin/env python3

''' 
    Need to make a separation of UDP and TCP searching, loading 2 different set of rules
'''

from util import Util
from io import BytesIO
from vault import Vault
from escapy import Escapy
from carver import Carver
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
    _rules = ""
    _url_rules = ""
    _matches = []
    udp_ports = ["53", "80", "443"]

    # Loads in uncompiled rules files
    @staticmethod
    def load_rules():
        rule_files = Yara._prepare_rules(RULES_DIR)
        url_rule_files = Yara._prepare_rules(INTEL_DIR)
        # Compile all rules file in specified paths
        try:
            Yara._rules = yara.compile(filepaths=rule_files)
            Yara._url_rules = yara.compile(filepaths=url_rule_files)
        except Exception as e:
            logger.error(f"Invalid Rule file/syntax error: \n{e} [{Thread.name()}]")

    # Prepare uncompile yara rules files
    @staticmethod
    def _prepare_rules(rules):
        results = {}
        for fname in glob.iglob(RULES_DIR+"**/*.yar", recursive=True):
            with open(fname, 'r') as f:
                results[os.path.basename(fname)[:-4]] = fname
        return results

    @staticmethod
    def run(stream_dict):
        # Yara.load_rules()
        matches = None
        carver = Carver()

        # might change this to use multiprocessing too - zen
        for k, stream in stream_dict.items():
            if (payload := extract_payload(stream)) is not None:
                raw_timestamp = Escapy.convert_packet(stream[0], "Timestamp")
                timestamp = str(datetime.datetime.utcfromtimestamp(raw_timestamp))

                cont_type, cont_length = carver.get_content_info(BytesIO(payload))
                if all([cont_type, cont_length]):
                    Vault.add_carving_queue(k, timestamp, cont_type, cont_length)

                try:
                    if (matches := Yara._rules.match(data=payload)):

                        if "url" in matches[0].rule:
                            Yara.url_yar(stream, k, payload, matches, timestamp)

                        Organize.add_stream_entry(k, stream, payload, matches, timestamp)
                except AttributeError:
                    logger.critical(f"Yara rules error, check rules in \"rules/custom_rules/<file>\" [{Thread.name()}]")

    '''
    function "url_yar(, stream, k, matches)" 

    E.g. 
    When there is a URL in an email (or in any stream payload), it will search through the "suspicious" or "malicious" urls/ips specified in threat_intel's yara rules, if matched, flag it

    '''

    @staticmethod
    def url_yar(stream, k, payload, matches, timestamp):
        for url in matches[0].strings:
            # theres an error right below this line, use pylint - zen
            if (matches := Yara._url_rules.match(data=url[2])):
                Organize.add_stream_entry(k, stream, payload, matches, timestamp)

    @staticmethod
    def scan_carved(k, timestamp, payload):
        try:
            if (matches := Yara._rules.match(data=payload)):

                if "url" in matches[0].rule:
                    Yara.url_yar(None, k, payload, matches, timestamp)

                Organize.add_stream_entry(k, None, payload, matches, timestamp)
        except AttributeError:
            logger.critical(f"Yara rules error, check rules in \"rules/custom_rules/<file>\" [{Thread.name()}]")


if __name__ == "__main__":
    #    RULES_DIR = "."+RULES_DIR
    #    CAP_PATH = "."+CAP_PATH

    pcap = Util.load_cap("testing2")
    stream_dict = find_streams(pcap)
    yar = Yara()
    yar.run(stream_dict)
