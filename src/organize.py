from util import Util
from vault import Vault
from thread import Thread

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
        flag_matches = []
        for match in yara_flagged[0].strings:
            try:
                flag_matches.append(match[2].decode('utf-8'))
            except:
                flag_matches.append(match[2])

        flagged_details = Payload_flagged(stream_key, stream, stream_payload, yara_flagged[0].strings, yara_flagged[0].rule, yara_flagged[0].tags)
        flagged_dict[timestamp] = flagged_details

        Vault.set_flagged(flagged_dict)
        logger.info(f"Payload: {flag_matches} --> {yara_flagged[0].rule} [{Thread.name()}]")

    @staticmethod
    def add_packet_entry(threat_packet, threat_flagged, timestamp):
        flagged_dict = {}
        flag_matches = []
        for match in threat_flagged[0].strings:
            flag_matches.append(match[2].decode('utf-8'))

        flagged_details = Threat_flagged(threat_packet, threat_flagged[0].strings, threat_flagged[0].rule, threat_flagged[0].tags)
        flagged_dict[timestamp] = flagged_details

        Vault.set_flagged(flagged_dict)
        logger.info(f"Threat: {flag_matches} --> {threat_flagged[0].rule} [{Thread.name()}]")


class Payload_flagged:
    def __init__(self, stream_id, stream, payload, strings, rule, tags):
        self.identifier = "payload"
        self.stream_id = stream_id
        self.stream = stream
        self.payload = payload
        self.strings = strings
        self.rule = rule
        self.tags = tags


class Threat_flagged:
    def __init__(self, packet, strings, rule, tags):
        self.identifier = "endpoint"
        self.packet = packet
        self.strings = strings
        self.rule = rule
        self.tags = tags
