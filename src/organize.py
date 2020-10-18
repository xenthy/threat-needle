from util import Util
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
        # Timestamp here might be inaccurate, as its only getting the first timestamp of the stream (multiple packets)
        flag_matches = []
        for match in yara_flagged[0].strings:
            flag_matches.append(match[2].decode('utf-8'))

        logger.info(f"Payload: {flag_matches} --> {yara_flagged[0].rule}")

    @staticmethod
    def add_packet_entry(threat_packet, threat_flagged, timestamp):
        flag_matches = []
        for match in threat_flagged[0].strings:
            flag_matches.append(match[2].decode('utf-8'))

        logger.info(f"Threat: {flag_matches} --> {threat_flagged[0].rule}")

