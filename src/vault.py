from scapy.plist import PacketList
from collections import Counter

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class Vault:

    __runtime_name = None
    __saving = False
    __threading_packet_list = PacketList()
    __saving_packet_list = PacketList()
    __mapping = Counter()
    __packet_count = 0
    __session_dict = {}
    __session_header = []
    __flagged_dict = {}
    __carved_files = []

    @staticmethod
    def set_runtime_name(runtime_name):
        Vault.__runtime_name = runtime_name

    @staticmethod
    def get_runtime_name():
        return Vault.__runtime_name

    @staticmethod
    def set_saving(saving):
        Vault.__saving = saving

    @staticmethod
    def get_saving():
        return Vault.__saving

    @staticmethod
    def refresh():
        Vault.__threading_packet_list = PacketList()
        Vault.__mapping = Counter()
        Vault.__packet_count = 0
        Vault.__session_dict = {}
        Vault.__session_header = []
        Vault.__flagged_dict = {}
        Vault.__carved_files = []

    @staticmethod
    def update_mapping(packet):
        try:
            tmp = sorted([packet[0][1].src, packet[0][1].dst])
            key = f"{tmp[0]},{tmp[1]}"
            Vault.__mapping.update([key])
            logger.debug(f"Packet #{sum(Vault.__mapping.values())}:" +
                         f"{packet[0][1].src} ==> {packet[0][1].dst}")
        except AttributeError:
            tmp = sorted([packet[0][0].src, packet[0][0].dst])
            key = f"{tmp[0]},{tmp[1]}"
            Vault.__mapping.update([key])
            logger.debug(f"Packet #{sum(Vault.__mapping.values())}:" +
                         f"{packet[0][0].src} ==> {packet[0][0].dst}")

    @staticmethod
    def get_mapping():
        ip_list = []
        for key in Vault.__mapping:
            ip1, ip2 = key.split(',')
            ip_list.append(ip1)
            ip_list.append(ip2)

        return Vault.__mapping, list(set(ip_list))

    @staticmethod
    def plist_append(packet):
        # increment total packet count
        Vault.__packet_count += 1
        Vault.__threading_packet_list.append(packet)
        if Vault.__saving:
            Vault.__saving_packet_list.append(packet)

    @staticmethod
    def get_threading_plist():
        temp = Vault.__threading_packet_list
        Vault.__threading_packet_list = PacketList()
        return temp

    @staticmethod
    def get_saving_plist():
        temp = Vault.__saving_packet_list
        Vault.__saving_packet_list = PacketList()
        return temp

    @staticmethod
    def get_sessions(reset=False):
        if not reset:
            return Vault.__session_dict
        temp = Vault.__session_dict
        Vault.__session_dict = {}
        return temp

    @staticmethod
    def add_session(stream_dict):
        for header, plist in stream_dict.items():
            Vault.__session_header += [header] if header not in\
                Vault.__session_header else []
            Vault.__session_dict[header] = Vault.__session_dict[header] +\
                plist if header in Vault.__session_dict else plist

    @staticmethod
    def get_session_headers():
        return Vault.__session_header

    @staticmethod
    def get_total_packet_count():
        return Vault.__packet_count

    @staticmethod
    def get_flagged() -> dict:
        return Vault.__flagged_dict

    @staticmethod
    def set_flagged(flagged_dict):
        Vault.__flagged_dict.update(flagged_dict)

    @staticmethod
    def add_carved_file(session_header, timestamp, filename, cont_type):
        Vault.__carved_files.append((session_header, timestamp,
                                     filename, cont_type))

    @staticmethod
    def get_carved_files() -> list:
        return Vault.__carved_files
