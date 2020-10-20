from util import Util
from escapy import Escapy
from pprint import pformat
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
from collections import OrderedDict
from pprint import pformat

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


# receive a list of packet in a stream and returns the payload
def extract_payload(stream, pure=False):
    payload = bytes()
    for pkt in stream:
        raw, http_request, http_response = Escapy.convert_packet(pkt, "Raw", "HTTP Request", "HTTP Response")

        if not pure:
            if http_request:
                payload += __http_helper(http_request, ["Method", "Path", "Http_Version"])

            if http_response:
                payload += __http_helper(http_response, ["Http_Version", "Status_Code", "Reason_Phrase"])

        if raw is not None:
            payload = payload + raw["load"]

    return payload if len(payload) != 0 else None


def __http_helper(dct, header) -> bytes:
    payload = bytes()
    payload = payload + dct[header[0]] + b" " + dct[header[1]] + b" " + dct[header[2]]
    for k, v in dct.items():
        if k in header or v is None or type(v) != bytes:
            continue
        payload = payload + b"\n" + k.encode() + b": " + v

    return payload + b"\n\n"


def find_streams(pcap):
    # get every session in the pcap file
    stream = pcap.sessions()
    stream_dict = OrderedDict()

    for k, v in stream.items():

        if 'TCP' in k or 'UDP' in k or 'ARP' in k:
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

        elif 'ARP' in k:
            inverse_key = k.split()

    # logger.info(f"{len(stream_dict)} streams found")
    return stream_dict


if __name__ == "__main__":
    pcap = Util.load_cap("2020-10-18_17-32-16")
    a = find_streams(pcap)
    for k, v in a.items():
        if 'ARP' in k:
            for x in v:
                print(x.show())
