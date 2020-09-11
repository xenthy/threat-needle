from config import PCAP_PATH
from scapy.all import wrpcap, rdpcap, PacketList

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
    def load_pcap(file_name) -> PacketList:
        try:
            pcap = rdpcap(f"{PCAP_PATH}{file_name}")
            logger.info(f"Pcap file LOADED: [{file_name}]")
            return pcap
        except FileNotFoundError as error:
            logger.warning(f"Loading Pcap failed! [{error}]")
            exit(1)

    @staticmethod
    def save_pcap(file_name, pcap) -> bool:
        try:
            wrpcap(f"{PCAP_PATH}{file_name}", pcap)
            logger.info(f"Pcap file SAVED: [{file_name}]")
        except FileNotFoundError as error:
            logger.warning(f"Saving Pcap failed! [{error}]")
            exit(1)
