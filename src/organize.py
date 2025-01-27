from vault import Vault
from thread import Thread

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP, LOG_LEVEL
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class Organize:
    stream_counter = 0
    packet_counter = 0

    @staticmethod
    def add_stream_entry(stream_key, stream, stream_payload, yara_flagged, timestamp):
        """
        Organized flagging for yara_process.py scanning of 
        - Streams
        - Payload Data
        """
        flagged_dict = {}
        flag_matches = []
        for match in yara_flagged[0].strings:
            try:
                flag_matches.append(match[2].decode('utf-8'))
            except:
                flag_matches.append(match[2])

        flagged_details = PayloadFlagged(yara_flagged, timestamp, stream_key, stream, stream_payload,
                                         yara_flagged[0].strings, yara_flagged[0].rule, yara_flagged[0].tags)
        Organize.packet_counter += 1
        flagged_dict[str(Organize.packet_counter)] = flagged_details

        Vault.set_flagged(flagged_dict)
        logger.info(f"Payload: {stream_key} --> {yara_flagged[0].rule} [{Thread.name()}]")

    @staticmethod
    def add_packet_entry(threat_packet, threat_flagged, timestamp):
        """
        Organized flagging for threat_intel.py scanning of 
        - Protocol layers in packets
        - Packet details
        - Packet contents
        """
        flagged_dict = {}
        flag_matches = []
        for match in threat_flagged[0].strings:
            flag_matches.append(match[2].decode('utf-8'))

        flagged_details = ThreatFlagged(threat_flagged, timestamp, threat_packet, threat_flagged[0].strings,
                                        threat_flagged[0].rule, threat_flagged[0].tags)
        Organize.packet_counter += 1
        flagged_dict[str(Organize.packet_counter)] = flagged_details

        Vault.set_flagged(flagged_dict)
        logger.info(f"Threat: {flag_matches} --> {threat_flagged[0].rule} [{Thread.name()}]")


class PayloadFlagged:
    def __init__(self, payload_flagged, timestamp, stream_id, stream, payload, strings, rule, tags):
        self.identifier = "payload"
        self.mal_type = payload_flagged
        self.timestamp = timestamp
        self.stream_id = stream_id
        self.stream = stream
        self.payload = payload
        self.strings = strings
        self.rule = rule
        self.tags = tags


class ThreatFlagged:
    def __init__(self, threat_flagged, timestamp, packet, strings, rule, tags):
        self.identifier = "endpoint"
        self.mal_type = threat_flagged
        self.timestamp = timestamp
        self.packet = packet
        self.strings = strings
        self.rule = rule
        self.tags = tags
