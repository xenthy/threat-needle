from scapy.all import wrpcap, rdpcap

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.info("__INIT__")


class Util:
    @staticmethod
    def load_pcap(file_path):
        pcap = rdpcap(file_path)
        logger.info(f"Pcap file loaded: {file_path}")
        return pcap
