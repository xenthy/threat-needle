from config import CAP_PATH, CAP_EXTENSION
from scapy.all import wrpcap, rdpcap, PacketList

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class Util:
    @staticmethod
    def load_cap(file_name) -> PacketList:
        try:
            cap = rdpcap(f"{CAP_PATH}{file_name}{CAP_EXTENSION}")
            logger.info(f"\"{file_name}{CAP_EXTENSION}\" loaded")
            return cap
        except FileNotFoundError as error:
            logger.warning(f"{type(error).__name__}: \"{format(error)}\"")
            exit(1)

    @staticmethod
    def save_cap(file_name, cap) -> bool:
        try:
            wrpcap(f"{CAP_PATH}{file_name}{CAP_EXTENSION}", cap)
            logger.info(f"\"{file_name}{CAP_EXTENSION}\" saved")
        except FileNotFoundError as error:
            logger.warning(f"{type(error).__name__}: \"{format(error)}\"")
            exit(1)
