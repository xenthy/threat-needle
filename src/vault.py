from scapy.all import PacketList

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class Vault:

    __interrupt = False
    __runtime_name = None
    __saving = False
    __threading_packet_list = PacketList()
    __saving_packet_list = PacketList()
    __packet_count = 0
    __session_dict = {}
    __session_header = []
    __flagged_dict = {}

    @staticmethod
    def set_interrupt(interrupt):
        Vault.__interrupt = interrupt

    @staticmethod
    def get_interrupt():
        return Vault.__interrupt

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
    def get_sessions():
        return Vault.__session_dict

    @staticmethod
    def add_session(stream_dict):
        for header, plist in stream_dict.items():
            Vault.__session_header += [header] if header not in Vault.__session_header else []
            Vault.__session_dict[header] = Vault.__session_dict[header] +\
                plist if header in Vault.__session_dict else plist

    @staticmethod
    def reset_session():
        Vault.__session_dict = {}

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
