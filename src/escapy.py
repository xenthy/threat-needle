"""
Insanely good wrapper for scapy. Aids in asynchronous sniffing and
extracting data in scapy.packets
"""

from os import name as os_name
from collections import OrderedDict
from scapy.all import AsyncSniffer
from scapy.plist import PacketList
from scapy.utils import wrpcap, rdpcap
from scapy.layers.http import HTTPRequest, HTTPResponse

from config import CAP_PATH, CAP_EXTENSION

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP, LOG_LEVEL
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class Escapy:
    """
    Insanely good wrapper for scapy. Aids in asynchronous sniffing and
    extracting data in scapy.packets
    """
    __packet_values = (int, float, str, bytes, bool, list,
                       tuple, set, dict, type(None))
    __explicit_layers = [HTTPRequest, HTTPResponse]
    __cap = PacketList()

    @staticmethod
    def async_sniff(action=None, count=0, store=False):
        """
        Sniffs packets asynchronously
        """
        # prepare for a fresh run (threading safety)
        Escapy.__cap = PacketList

        # enable monitor mode on linux based systems
        monitor_mode = not os_name == "nt"
        logger.info(f"Monitor Mode: [{monitor_mode}]")

        Escapy.__cap = AsyncSniffer(prn=action, monitor=monitor_mode,
                                    count=count, store=store)
        Escapy.__cap.start()

    @staticmethod
    def stop():
        """
        Stop async_sniff()
        """
        Escapy.__cap.stop()
        Escapy.__cap.join()

    @staticmethod
    def get_cap():
        """
        Returns the scapy async_sniff "thread"
        """
        return Escapy.__cap

    @staticmethod
    def load_cap(file_name) -> PacketList:
        """
        Load .cap into scapy.plist
        """
        try:
            cap = rdpcap(f"{CAP_PATH}{file_name}{CAP_EXTENSION}")
            logger.info(f"\"{file_name}{CAP_EXTENSION}\" loaded")
            return cap
        except FileNotFoundError as error:
            logger.warning(f"{type(error).__name__}: \"{format(error)}\"")

    @staticmethod
    def save_cap(file_name, cap) -> bool:
        """
        Save scapy.plist into .cap
        """
        try:
            wrpcap(f"{CAP_PATH}{file_name}{CAP_EXTENSION}", cap)
            logger.info(f"\"{file_name}{CAP_EXTENSION}\" saved")
        except FileNotFoundError as error:
            logger.warning(f"{type(error).__name__}: \"{format(error)}\"")

    @staticmethod
    def convert_packet(packet, *args, explicit_layers=[]) -> OrderedDict:
        """
        Converts "scapy.layers.l2.Ether" to a dictionary form factor
        """
        explicit_layers = Escapy.__explicit_layers + explicit_layers
        packet_dict = OrderedDict()
        count = 0

        # default scapy layers
        while (layer := packet.getlayer(count)):
            count += 1

            # if layer is not required
            if len(args) != 0 and layer.name not in args:
                continue

            # if layer returns no data
            if (layer_dict := Escapy.__layer_dict(layer)) is None:
                continue

            # concatenate dictionaries
            packet_dict = {**packet_dict, **layer_dict}

        # explicit layers
        for protocol_layer in explicit_layers:
            layer = packet.getlayer(protocol_layer)
            if (layer_dict := Escapy.__layer_dict(layer)) is not None:
                packet_dict = {**packet_dict, **layer_dict}

        # metadata
        packet_dict["Timestamp"] = packet.time
        packet_dict["Size"] = packet.__len__()

        # return if no explicit layers are requested
        if len(args) == 0:
            return packet_dict

        # if explicit layers are required
        return_list = []

        # order return list
        for arg in args:
            return_list.append(packet_dict[arg] if arg in packet_dict else None)

        return return_list[0] if len(args) == 1 else return_list

    @staticmethod
    def __layer_dict(layer):
        """
        Returns a dictionary of a layer
        """
        if not getattr(layer, 'fields_desc', None):
            return None

        layer_dict = {}

        # loop through each layer and find more layers
        for key in layer.fields_desc:
            value = getattr(layer, key.name)
            value = None if value is type(None) else value

            if not isinstance(value, Escapy.__packet_values):
                value = Escapy.__layer_dict(value)

            layer_dict[key.name] = value

        return {layer.name: layer_dict}


def init_test_sniffer():
    """
    For testing
    """
    # packets = AsyncSniffer(monitor=True, count=0)
    packets = AsyncSniffer(count=0)
    packets.start()

    input("Press enter to stop sniffing: ")

    packets.stop()
    packets.join()


if __name__ == "__main__":
    init_test_sniffer()
