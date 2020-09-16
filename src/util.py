from config import CAP_PATH, CAP_EXTENSION
from scapy.all import wrpcap, rdpcap, PacketList

from collections import OrderedDict

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

    @staticmethod
    def convert_packet(packet) -> OrderedDict:
        """
        Converts "scapy.layers.l2.Ether" to a dictionary of dictionaries of packet information
        """
        # init dictionary of dictionaries
        packet_dict = OrderedDict()

        string_packet = packet.__repr__()
        packet_type = string_packet.split("|<")

        # remove header, "<"
        packet_type[0] = packet_type[0][1:]

        # remove trailer, e.g. (|>>>>)
        index = packet_type[-1].find("|")
        packet_type[-1] = packet_type[-1][:index].strip()

        for layer in packet_type:
            layer_list = layer.split()

            # remove catergory name
            layer_name = layer_list.pop(0)

            # if it is 'Raw', or 'Padding' join the payload back together
            if layer_name in ["Raw", "Padding"]:
                layer_list = ["".join(layer_list)]

            # init dictionary
            layer_dict = OrderedDict()

            for item in layer_list:
                # get key and value for each item
                try:
                    key, value = item.split("=", 1)
                except ValueError:
                    continue
                if layer_name in ["Raw", "Padding"]:
                    layer_dict[key] = value[1:-1]
                else:
                    layer_dict[key] = value

            packet_dict[layer_name] = layer_dict

        return packet_dict
