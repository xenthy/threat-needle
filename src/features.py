from util import Util
from pprint import pformat
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
from collections import OrderedDict

from scapy.all import Raw

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


# receive a list of packet in a stream and returns the payload
def extract_payload(stream):
    payload = bytes()
    for pkt in stream:
        # dict_pkt = Util.convert_packet(pkt)
        # if 'Raw' in dict_pkt.keys() and 'load' in dict_pkt['Raw'].keys():
        #     payload = payload + dict_pkt['Raw']['load'].replace("\\n", "\n").replace("\\r", " ")
        if pkt.haslayer(Raw):
            payload += pkt.getlayer(Raw).load
    # return Util.convert_to_hex(payload)
    # logger.info(payload)
    return payload

# receives a PacketList and returns a dictionary of streams
# dict_stream[key] = value
# key = [IP IP portnumber] , value = list of Packet in the stream order


def find_streams(pcap):
    # get every session in the pcap file
    stream = pcap.sessions()
    stream_dict = OrderedDict()

    for k, v in stream.items():

        if 'TCP' in k or 'UDP' in k:
            inverse_key = k.split()
            inverse_key[1], inverse_key[3] = inverse_key[3], inverse_key[1]
            inverse_key.pop(2)
            inverse_key = " ".join(inverse_key)

            if inverse_key in stream_dict:

                tmp_pkt_list = stream_dict[inverse_key]
                combined_packets = []

                for packet in v:
                    try:
                        while packet.time > tmp_pkt_list[0].time:
                            combined_packets.append(tmp_pkt_list.pop(0))
                        else:
                            combined_packets.append(packet)
                    except:
                        combined_packets.append(packet)

                stream_dict[inverse_key] = combined_packets + tmp_pkt_list

            else:
                packets = []
                for packet in v:
                    packets.append(packet)

                tmp = k.split()
                tmp.pop(2)
                tmp = " ".join(tmp)
                stream_dict[tmp] = packets

    # logger.info(f"{len(stream_dict)} streams found")
    return stream_dict


if __name__ == "__main__":

    pcap = Util.load_cap("ftp")
    stream_dict = find_streams(pcap)

    for k, stream in stream_dict.items():
        # extract_payload(stream)
        logger.info(f"{extract_payload(stream)}\n\n\n")
