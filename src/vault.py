from scapy.all import PacketList


class Vault:

    __interrupt = False
    __saving = False
    __threading_packet_list = PacketList()
    __saving_packet_list = PacketList()
    __packet_count = 0
    __session_dict = {}

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
            Vault.__session_dict[header] = Vault.__session_dict[header] +\
                plist if header in Vault.__session_dict else plist

    @staticmethod
    def get_total_packet_count():
        return Vault.__packet_count
