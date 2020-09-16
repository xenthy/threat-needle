from vault import Vault
from util import Util

from pprint import pformat
import time
import threading
import copy
from scapy.all import PacketList

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
    Vault.plist_append(packet)

    # Create tuple of Src/Dst in sorted order
    try:
        key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
        packet_counts.update([key])
        logger.info(f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}")
    except AttributeError:
        key = tuple(sorted([packet[0][0].src, packet[0][0].dst]))
        packet_counts.update([key])
        logger.info(f"Packet #{sum(packet_counts.values())}: {packet[0][0].src} ==> {packet[0][0].dst}")


def efficient(lock):
    while True:
        if Vault.get_interrupt():
            break

        lock.acquire()
        temp_plist = Vault.get_threading_plist()
        temp_count = len(temp_plist)
        Vault.add_count(temp_count)
        lock.release()

        time.sleep(5)  # 2 seconds


def main():
    """ threading test """
    Vault.set_interrupt(False)
    lock = threading.Lock()
    efficient_thread = threading.Thread(target=efficient, args=(lock, ), daemon=True)

    """ indefinite sniffing """
    Sniffer.start(custom_action)
    # Sniffer.start()

    efficient_thread.start()

    input("Press enter to stop sniffing: ")

    Vault.set_interrupt(True)
    Sniffer.stop()
    efficient_thread.join()

    temp_plist = Vault.get_threading_plist()
    temp_count = len(temp_plist)
    Vault.add_count(temp_count)
    logger.debug(temp_count)

    # cap = Sniffer.get_cap().results  # depreciated
    cap = Vault.get_complete_plist()

    """ mapping """
    # Print out packet count per A <--> Z address pair
    logger.info("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))

    """ saving """
    # save sniffed packets to cap file
    Util.save_cap(str(time.ctime(time.time())).replace(":", "-"), cap)

    """ misc logging """
    logger.info(cap)
    logger.debug(f"Async: {len(cap)}")
    logger.debug(f"Custom Plist: {len(Vault.get_complete_plist())}")
    logger.debug(f"Custom Count: {Vault.get_count()}")
    logger.debug("All 3 numbers above should be the same")

    """ dissect packets """
    for packet in cap:
        converted = Util.convert_packet(packet)
        logger.info(pformat((converted)))


if __name__ == "__main__":
    main()
    logger.info("__EOF__")
