import datetime
from escapy import Escapy
from yara_create import Rule
from config import INTEL_DIR
from organize import Organize
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP, LOG_LEVEL
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class ThreatIntel:
    def __init__(self):
        self.rules = ""
        self.threat_list = {}

    def run(self, temp_plist):
        """
        Main function to run ThretIntel
        """
        for packet in temp_plist:
            timestamp, extracted = self.extract_ip_domains(packet)
            if extracted:
                self.hunt_threat(timestamp, extracted, packet)

    def extract_ip_domains(self, packet):
        """
        Retrieving the DNS, IP and HTTP_REQUEST layers of the packet
        - To extract Domains and IPs
        """
        extracted = []
        http_request, dns, ip_layer, timestamp = Escapy.convert_packet(packet, "HTTP Request", "DNS", "IP", "Timestamp")

        if http_request:
            extracted.append(http_request["Host"].decode('utf-8') + http_request["Path"].decode('utf-8'))

        if dns:
            try:
                extracted.append(dns["qd"]["DNS Question Record"]["qname"].decode('utf-8'))  # bytes
            except TypeError:
                pass

        if ip_layer:
            extracted.append(ip_layer["src"])
            extracted.append(ip_layer["dst"])

        return timestamp, extracted

    def hunt_threat(self, raw_timestamp, found, packet):
        """
        Use yara to scan the extracted Domain and/or IP found in the packet and details
        """
        timestamp = str(datetime.datetime.utcfromtimestamp(raw_timestamp))
        for threat in found:
            if (matches := self.rules.match(data=threat)):
                self.threat_list[threat] = [packet]
                Organize.add_packet_entry(packet, matches, timestamp)

                # To prevent multiple flags (TBC)
                # if threat not in self.threat_list:
                # self.threat_list[threat] = [packet]
                # Organize.add_packet_entry(threat, packet, matches, timestamp)
                # else:
                # self.threat_list[threat] = self.threat_list[threat] + [packet]

    def threat_update(self):
        """
        Updating of the Compiled yara rules of threat_intel 
        - Malicious Domains
        - Malicious IPs
        """
        filenames = Rule.prepare_lists()
        entries = {"domains": [], "ips": []}
        for filename in filenames:
            identify = filename.split("_")[1]
            with open(INTEL_DIR+filename+".txt", "r") as file_obj:
                lines = [line.strip() for line in file_obj.readlines() if "#" not in line if line.strip() != ""]

            if identify == "domain":
                entries["domains"] += lines
            elif identify == "ip":
                entries["ips"] += lines

        for entry, lines in entries.items():
            chunked = Rule.chunker(lines, 9999)
            for index, chunk in enumerate(chunked):
                name = entry+str(index)
                tag = "emerging_"+entry
                author = "Auto Generated"
                purpose = "Threat Intel Domains/IPs"
                if entry == "domains":
                    category = "domains_"+str(index)
                elif entry == "ips":
                    category = "ips_"+str(index)

                Rule.add_rule(name, tag, author, purpose, chunk, category)

        self.rules = Rule.load_rules()
