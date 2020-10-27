#!/usr/bin/env python3

import re
import glob
import datetime
from escapy import Escapy
from yara_create import *
from config import INTEL_DIR
from organize import Organize
from features import extract_payload, find_streams
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class ThreatIntel:
    def __init__(self):
        self.rules = ""
        self.threat_list = {}

    def run(self, temp_plist):
        for packet in temp_plist:
            timestamp, extracted = self.extract_ip_domains(packet)
            if extracted:
                self.hunt_threat(timestamp, extracted, packet)

    def extract_ip_domains(self, packet):
        extracted = []

        http_request, dns, ip, timestamp = Escapy.convert_packet(packet, "HTTP Request", "DNS", "IP", "Timestamp")

        if http_request:
            print(http_request["Host"])
            extracted.append(http_request["Host"].decode('utf-8') + http_request["Path"].decode('utf-8'))

        if dns:
            try:
                extracted.append(dns["qd"]["DNS Question Record"]["qname"].decode('utf-8'))  # bytes
            except TypeError:
                pass

        if ip:
            extracted.append(ip["src"])
            extracted.append(ip["dst"])

        return timestamp, extracted

    def hunt_threat(self, raw_timestamp, found, packet):
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
        filenames = Rule.prepare_lists()
        entries = {"domains": [], "ips": []}
        for filename in filenames:
            identify = filename.split("_")[1]
            with open(INTEL_DIR+filename+".txt", "r") as f:
                lines = [line.strip() for line in f.readlines() if "#" not in line if line.strip() != ""]

            if "domain" == identify:
                entries["domains"] += lines
            elif "ip" == identify:
                entries["ips"] += lines

        for entry, lines in entries.items():
            chunked = Rule.chunker(lines, 9999)
            for index, chunk in enumerate(chunked):
                name = entry+str(index)
                tag = "emerging_"+entry
                author = "Auto Generated"
                purpose = "Threat Intel Domains/IPs"
                if "domains" == entry:
                    category = "domains_"+str(index)
                elif "ips" == entry:
                    category = "ips_"+str(index)

                Rule.add_rule(name, tag, author, purpose, chunk, category)

        self.rules = Rule.load_rules()

    # def get_threats(self):
        # if self.threat_list:
            # return self.threat_list


if __name__ == "__main__":
    threat = ThreatIntel()
    pass
