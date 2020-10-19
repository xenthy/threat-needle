from util import Util
from vault import Vault
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

class Organize:
    @staticmethod
    def add_stream_entry(stream_key, stream, stream_payload, yara_flagged, timestamp):
        flagged_dict = {}
        # Timestamp here might be inaccurate, as its only getting the first timestamp of the stream (multiple packets)
        flag_matches = []
        for match in yara_flagged[0].strings:
            flag_matches.append(match[2].decode('utf-8'))

        flagged_details = Payload_flagged(stream_key, stream, stream_payload, yara_flagged[0].strings, yara_flagged[0].rule, yara_flagged[0].tags) 
        flagged_dict[timestamp] = flagged_details

        Vault.set_flagged(flagged_dict)
        logger.info(f"Payload: {flag_matches} --> {yara_flagged[0].rule}")

    @staticmethod
    def add_packet_entry(threat_packet, threat_flagged, timestamp):
        flagged_dict = {}
        flag_matches = []
        for match in threat_flagged[0].strings:
            flag_matches.append(match[2].decode('utf-8'))

        flagged_details = Threat_flagged(threat_packet, threat_flagged[0].strings, threat_flagged[0].rule, threat_flagged[0].tags) 
        flagged_dict[timestamp] = flagged_details

        Vault.set_flagged(flagged_dict)
        logger.info(f"Threat: {flag_matches} --> {threat_flagged[0].rule}")


class Payload_flagged:
    def __init__(self, stream_id, stream, payload, strings, rule, tags):
        self.identifier = "payload"
        self.stream_id = stream_id
        self.stream = stream 
        self.payload = payload
        self.strings = strings
        self.rule = rule
        self.tags = tags

    # Identifier of this Object, steam or packet
    def get_identifier(self):
        return self.identifier

    # Returns the stream's src and dst (stream header)
    def get_stream_id(self):
        return self.stream_id

    # Returns the stream that yara flagged
    def get_stream(self):
        return self.stream

    # Returns the payload extracted from the stream, that was flagged
    def get_payload(self):
        return self.payload

    # Returns the strings matched my yara 
    # e.g. [(10L,'$a','xyz')]
    def get_strings(self) -> list:
        return self.matched_strings

    # Returns the rule name of the yara rule that was used to flag
    def get_rule(self):
        return self.rule

    # Returns the tag of the yara rule that was used to flag
    def get_tags(self) -> list:
        return self.tags


class Threat_flagged:
    def __init__(self, packet, strings, rule, tags):
        self.identifier = "endpoint"
        self.packet = packet
        self.strings = strings
        self.rule = rule
        self.tags = tags

    # Identifier of this Object, steam or packet
    def get_identifier(self):
        return self.identifier

    # Returns the strings matched my yara 
    # e.g. [(10L,'$a','xyz')]
    def get_strings(self) -> list:
        return self.matched_strings

    # Returns the rule name of the yara rule that was used to flag
    def get_rule(self):
        return self.rule

    # Returns the tag of the yara rule that was used to flag
    # e.g. ['mail']
    def get_tags(self) -> list:
        return self.tags