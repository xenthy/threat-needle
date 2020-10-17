from os import name as os_name
from scapy.all import AsyncSniffer, PacketList
from collections import OrderedDict

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class Escapy:
    __packet_values = (int, float, str, bytes, bool, list, tuple, set, dict, type(None))
    __cap = PacketList()

    @staticmethod
    def async_sniff(action=None, count=0, store=False):
        # prepare for a fresh run (threading safety)
        Escapy.__cap = PacketList

        # enable monitor mode on linux based systems
        monitor_mode = False if os_name == "nt" else True
        logger.info(f"Monitor Mode: [{monitor_mode}]")

        Escapy.__cap = AsyncSniffer(prn=action, monitor=monitor_mode, count=count, store=store)
        Escapy.__cap.start()

    @staticmethod
    def stop():
        Escapy.__cap.stop()
        Escapy.__cap.join()

    @staticmethod
    def get_cap():
        return Escapy.__cap

    @staticmethod
    def convert_packet(packet, *args, explicit_layers=[]) -> OrderedDict:
        packet_dict = OrderedDict()
        count = 0

        # normal layers
        while (layer := packet.getlayer(count)):
            count += 1

            if (layer_dict := Escapy.__layer_dict(layer)) is None:
                continue

            packet_dict = {**packet_dict, **layer_dict}

        # explicit layers
        for protocol_layer in explicit_layers:
            layer = packet.getlayer(protocol_layer)
            if (layer_dict := Escapy.__layer_dict(layer)) is not None:
                packet_dict = {**packet_dict, **layer_dict}

        if len(args) == 0:
            return packet_dict

        # if specific layers are required
        return_list = []

        for arg in args:
            return_list.append(packet_dict[arg] if arg in packet_dict else None)

        return return_list[0] if len(args) == 1 else return_list

    @staticmethod
    def __layer_dict(layer):
        layer_dict = {}

        if not getattr(layer, 'fields_desc', None):
            return

        for key in layer.fields_desc:
            value = getattr(layer, key.name)
            value = None if value is type(None) else value

            if not isinstance(value, Escapy.__packet_values):
                value = Escapy.__layer_dict(value)

            layer_dict[key.name] = value

        return {layer.name: layer_dict}


def init_test_sniffer():
    # packets = AsyncSniffer(monitor=True, count=0)
    packets = AsyncSniffer(count=0)
    packets.start()

    input("Press enter to stop sniffing: ")

    packets.stop()
    packets.join()


if __name__ == "__main__":
    init_test_sniffer()
