from collections import Counter
from scapy.all import sniff, wrpcap, rdpcap


from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

# Create a Packet Counter
packet_counts = Counter()

# Define our Custom Action function


def custom_action(packet):
    # Create tuple of Src/Dst in sorted order
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    packet_counts.update([key])
    logger.info(
        f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}")


def init_sniffer():
    # Setup sniff, filtering for IP traffic
    # sniff(filter="ip", monitor=True, prn=custom_action, count=100)
    packets = sniff(filter="ip", prn=custom_action, count=100)

    # Print out packet count per A <--> Z address pair
    logger.info("\n".join(
        f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))

    # basic sniffing
    # packets = sniff(count=10, monitor=True)
    # logger.info(packets)

    # save sniffed packets to pcap file
    wrpcap('sniffed.pcap', packets)
    logger.info("Save Pcap to disk")

    # load from pcap file
    # packets = rdpcap('sniffed.pcap')
    # logger.info("Pcap loaded from disk")


if __name__ == "__main__":
    init_sniffer()
