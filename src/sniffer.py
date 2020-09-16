from os import name as os_name
from scapy.all import AsyncSniffer, PacketList

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class Sniffer:
    __cap = PacketList()

    @staticmethod
    def start(action=None):
        # prepare for a fresh run (threading safety)
        Sniffer.__cap = PacketList

        # enable monitor mode on linux based systems
        monitor_mode = False if os_name == "nt" else True
        logger.info(f"Monitor Mode: [{monitor_mode}]")

        Sniffer.__cap = AsyncSniffer(prn=action, monitor=monitor_mode, count=0)
        Sniffer.__cap.start()

    @staticmethod
    def stop():
        Sniffer.__cap.stop()
        Sniffer.__cap.join()

    @staticmethod
    def get_cap():
        return Sniffer.__cap


def init_test_sniffer():
    # packets = AsyncSniffer(monitor=True, count=0)
    packets = AsyncSniffer(count=0)
    packets.start()

    input("Press enter to stop sniffing: ")

    packets.stop()
    packets.join()


if __name__ == "__main__":
    init_test_sniffer()
