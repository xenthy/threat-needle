from vault import Vault
from util import Util

from pprint import pformat

from sniffer import Sniffer
from collections import Counter

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.info("__INIT__")

# Create a Packet Counter
packet_counts = Counter()


def custom_action(packet):
    # Create tuple of Src/Dst in sorted order
    try:
        key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
        packet_counts.update([key])
        logger.info(
            f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}")
    except AttributeError as error:
        logger.warning(f"{type(error).__name__}: \"{format(error)}\"")


def main():
    Sniffer.init()
    Sniffer.start(custom_action)

    input("Press enter to stop sniffing: ")

    Sniffer.stop()
    cap = Sniffer.get_cap()

    # Print out packet count per A <--> Z address pair
    logger.info("\n".join(
        f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))

    # save sniffed packets to cap file
    Util.save_cap("sniffed", cap.results)

    logger.info(cap.results)


if __name__ == "__main__":
    main()
    logger.info("__EOF__")
