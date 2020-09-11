from util import Util

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


def test():
    pcap = Util.load_pcap("test.pcap")
    logger.info(pcap)

    Util.save_pcap("test.pcap", pcap)


if __name__ == "__main__":
    test()
