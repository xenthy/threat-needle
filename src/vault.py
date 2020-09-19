import copy
from scapy.all import PacketList


class Vault:

    __interrupt = False
    __saving = False
    __threading_packet_list = PacketList()
    __saving_packet_list = PacketList()
    __debug_count = 0

    @staticmethod
    def set_interrupt(interrupt):
        Vault.__interrupt = interrupt

    @staticmethod
    def get_interrupt():
        return Vault.__interrupt

    @staticmethod
    def set_saving(saving):
        Vault.__saving = saving

    @staticmethod
    def get_saving():
        return Vault.__saving

    @staticmethod
    def plist_append(packet):
        Vault.__threading_packet_list.append(packet)
        if Vault.__saving:
            Vault.__saving_packet_list.append(packet)

    @staticmethod
    def get_threading_plist():
        temp = copy.deepcopy(Vault.__threading_packet_list)
        Vault.__threading_packet_list.clear()
        return temp

    @staticmethod
    def get_saving_plist():
        temp = copy.deepcopy(Vault.__saving_packet_list)
        Vault.__saving_packet_list.clear()
        return temp

    @staticmethod
    def add_count(count):
        Vault.__debug_count += count

    @staticmethod
    def get_count():
        return Vault.__debug_count
