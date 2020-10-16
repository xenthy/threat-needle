from util import Util
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

class Organize:
    def __init__(self):
        self.flagged = {}
        self.threats = {}
    
    def add_stream_entry(self, stream_key, stream_payload, yara_flagged):
        logger.info(f"Key: {stream_key} --> {yara_flagged[0].rule}")

    def add_packet_entry(self, threat_ip, threat_packet, threat_flagged):
        logger.info(f"Threat: {threat_ip} --> {threat_flagged[0].rule}")

if __name__ == "__main__":
    pass
