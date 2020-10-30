import os
import glob
import datetime
from io import BytesIO
import yara
from vault import Vault
from escapy import Escapy
from carver import Carver
from thread import Thread, thread
from organize import Organize
from features import extract_payload
from config import RULES_DIR, INTEL_DIR

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

    @staticmethod
    def load_rules():
        """
        Loads in yara rules files (.yar)
        - Errors on invalid syntax during yara rules compilation
        """
        rule_files = Yara._prepare_rules(RULES_DIR)
        url_rule_files = Yara._prepare_rules(INTEL_DIR)
        # Compile all rules file in specified paths
        try:
            Yara._rules = yara.compile(filepaths=rule_files)
            Yara._url_rules = yara.compile(filepaths=url_rule_files)
        except Exception as error:
            logger.error(f"Invalid Rule file/syntax error: \n{error} [{Thread.name()}]")

    @staticmethod
    def _prepare_rules(directory):
        """
        Prepare uncompile yara rules files
        """
        results = {}
        for fname in glob.iglob(directory+"**/*.yar", recursive=True):
            if os.path.isfile(fname):
                results[os.path.basename(fname)[:-4]] = fname
        return results

    @staticmethod
    def run(stream_dict):
        """
        Main start method for initializing the Yara scanning of packet's stream and payload data
        """
        matches = None

        for k, stream in stream_dict.items():
            Yara.carving(k, stream)
            Yara.raw_scan(k, stream)

        
    @staticmethod
    @thread(daemon=True)
    def carving(k, stream):
        for pkt in stream:
            if (payload := extract_payload([pkt], headers=True)) is not None:
                cont_type, cont_length = Carver.get_content_info(BytesIO(payload))
                raw_timestamp = Escapy.convert_packet(stream[0], "Timestamp")
                timestamp = str(datetime.datetime.utcfromtimestamp(raw_timestamp))

                if all([cont_type, cont_length]):
                    payload = extract_payload(stream, pure=True)
                    Carver.carve_stream(k, timestamp, cont_type, cont_length, payload)

    @staticmethod
    @thread(daemon=True)
    def raw_scan(k, stream):
        if (payload := extract_payload(stream)) is not None:
            raw_timestamp = Escapy.convert_packet(stream[0], "Timestamp")
            timestamp = str(datetime.datetime.utcfromtimestamp(raw_timestamp))

            try:
                if (matches := Yara._rules.match(data=payload)):
                    if "url" in matches[0].rule:
                        Yara.url_yar(stream, k, payload, matches, timestamp)

                    Organize.add_stream_entry(k, stream, payload, matches, timestamp)
            except AttributeError:
                logger.critical(f"Yara rules error, check rules [{Thread.name()}]")

  
    @staticmethod
    def url_yar(stream, k, payload, matches, timestamp):
        """
        Yara scanning for any malicious Domains or IPs in the stream captured
        E.g. When there is a URL in an email (or in any stream payload)
        """
        for url in matches[0].strings:
            # theres an error right below this line, use pylint - zen
            if (matches := Yara._url_rules.match(data=url[2])):
                Organize.add_stream_entry(k, stream, payload, matches, timestamp)

    @staticmethod
    def scan_carved(k, timestamp, payload):
        """
        Yara scanning of carved files
        """
        try:
            if (matches := Yara._rules.match(data=payload)):

                if "url" in matches[0].rule:
                    Yara.url_yar(None, k, payload, matches, timestamp)

                Organize.add_stream_entry(k, None, payload, matches, timestamp)
        except AttributeError:
            logger.critical(f"Yara rules error, check rules [{Thread.name()}]")
