import sys
import datetime
from collections import OrderedDict
from scapy.plist import PacketList, Packet
from scapy.utils import wrpcap, rdpcap
from scapy.layers.http import HTTPRequest, HTTPResponse

from config import DATETIME_FORMAT, CAP_PATH, CAP_EXTENSION, SESSION_CACHE_PATH
from vault import Vault

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP, LOG_LEVEL
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class Util:
    @staticmethod
    def datetime_to_string():
        return datetime.datetime.now().strftime(DATETIME_FORMAT)

    @staticmethod
    def load_cap(file_name) -> PacketList:
        try:
            cap = rdpcap(f"{CAP_PATH}{file_name}{CAP_EXTENSION}")
            logger.info(f"\"{file_name}{CAP_EXTENSION}\" loaded")
            return cap
        except FileNotFoundError as error:
            logger.warning(f"{type(error).__name__}: \"{format(error)}\"")

    @staticmethod
    def save_cap(file_name, cap) -> bool:
        try:
            wrpcap(f"{CAP_PATH}{file_name}{CAP_EXTENSION}", cap)
            logger.info(f"\"{file_name}{CAP_EXTENSION}\" saved")
        except FileNotFoundError as error:
            logger.warning(f"{type(error).__name__}: \"{format(error)}\"")

    @staticmethod
    def start_saving():
        logger.info("Initalising saving to file...")
        Util.file_name = Util.datetime_to_string()
        Vault.set_saving(True)

    @staticmethod
    def stop_saving():
        logger.info("Terminating saving to file...")
        Vault.set_saving(False)
        Util.save_cap(Util.file_name, Vault.get_saving_plist())

    @staticmethod
    def tail(filename, N):
        chunk = ""
        with open(filename, "r") as file:
            for line in (file.readlines()[-N:]):
                chunk += line
        return chunk

    @staticmethod
    def convert_to_hex(string):
        hex_format = ""
        skip = 0

        for index, char in enumerate(string):
            if skip > 0:
                skip -= 1
                continue
            if char == "\\" and index + 1 > len(string):
                break
            if char == "\\" and string[index+1] == "x":
                hex_format += string[index+2] + string[index+3]
                skip = 3
            else:
                char_hex = hex(ord(char))[2:]
                hex_format += "0"*(2 - len(char_hex)) + char_hex

            hex_format += " "

        return hex_format.strip()

    @staticmethod
    def get_size(obj, seen=None):
        """Recursively finds size of objects"""
        size = sys.getsizeof(obj)
        if seen is None:
            seen = set()
        obj_id = id(obj)
        if obj_id in seen:
            return 0
        seen.add(obj_id)
        if isinstance(obj, dict):
            size += sum([Util.get_size(v, seen) for v in obj.values()])
            size += sum([Util.get_size(k, seen) for k in obj.keys()])
        elif hasattr(obj, '__dict__'):
            size += Util.get_size(obj.__dict__, seen)
        elif hasattr(obj, '__iter__') and not isinstance(obj,
                                                         (str, bytes, bytearray)):
            size += sum([Util.get_size(i, seen) for i in obj])
        return size

    @staticmethod
    @DeprecationWarning
    def convert_packet(packet, *args) -> OrderedDict:
        """
        Converts "scapy.layers.l2.Ether" to a dictionary of
        dictionaries of packet information
        """
        string_packet = packet.__repr__()

        packet_type = string_packet.split("|<")

        # remove header, "<"
        packet_type[0] = packet_type[0][1:]

        # remove trailer, e.g. (|>>>>)
        index = packet_type[-1].rfind("|")
        packet_type[-1] = packet_type[-1][:index].strip()

        # if a specific value was specified
        if args:
            return Util.__conditional_convert(packet_type, args)

        # init dictionary of dictionaries
        packet_dict, layer_dict = OrderedDict(), OrderedDict()

        for layer in packet_type:
            # split into respective layers
            layer_list = layer.split()

            # remove catergory name
            layer_name = layer_list.pop(0)
            # if it is 'Raw', or 'Padding' join the payload back together
            if layer_name in ["Raw", "Padding"]:
                layer_list = [" ".join(layer_list)]

            for item in layer_list:
                # get key and value for each item
                try:
                    key, value = item.split("=", 1)
                except ValueError:
                    continue
                layer_dict[key] = value[1:-1] if layer_name in\
                    ["Raw", "Padding"] else value

            # finally, add sanitized later into dict
            packet_dict[layer_name] = layer_dict

        # misc information
        packet_dict["Timestamp"] = packet.time
        packet_dict["Size"] = len(packet)
        return packet_dict

    @classmethod
    @DeprecationWarning
    def __conditional_convert(self, packet_type, args):
        # init dictionary
        return_list = []

        # populate list with Nones
        while len(args) != len(return_list):
            return_list.append(None)
        logger.info(packet_type)
        for layer in packet_type:
            # split into respective layers
            layer_list = layer.split()

            # remove catergory name and check against key1
            if (layer_name := layer_list.pop(0)) not in args:
                continue

            # if it is 'Raw', or 'Padding' join the payload back together
            if layer_name in ["Raw", "Padding"]:
                layer_list = [" ".join(layer_list)]

            layer_dict = {}

            for item in layer_list:
                # get key and value for each item
                try:
                    key, value = item.split("=", 1)
                    layer_dict[key] = value[1:-1] if layer_name in\
                        ["Raw", "Padding"] else value
                except ValueError:
                    continue

            return_list[args.index(layer_name)] = layer_dict

        return return_list[0] if len(return_list) == 1 else return_list
