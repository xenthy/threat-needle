#!/usr/bin/env python3

import argparse
import random
import subprocess
import threading


def ip_worker(file, index):
    while "#" in (random_ip := random.choice(file).strip()):
        continue
    subprocess.run(["ping", "-c", "1", "-w", "1", random_ip], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    print(f"[!] ip[{index + 1}] probed {random_ip}")


def url_worker(file, index):
    while "#" in (random_url := random.choice(file).strip()):
        continue
    subprocess.run(["nslookup", random_url], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    print(f"[!] url[{index + 1}] probed {random_url}")


""" START """
parser = argparse.ArgumentParser(description="Simulate threats",
                                 prog=__file__[2:])
parser.add_argument("--ip", "-i",
                    default=0,
                    type=int,
                    dest="ip_count",
                    help="number of IPs to probe (>= 0)")
parser.add_argument("--url", "-u",
                    default=0,
                    type=int,
                    dest="url_count",
                    help="number of URLs to probe (>= 0)")

args = parser.parse_args()

ip, url = args.ip_count, args.url_count

if ip < 0 and url < 0:
    parser.error("IP and URL count has to be more than 0")
if ip < 0:
    parser.error("IP count has to be more than 0")
if url < 0:
    parser.error("URL count has to be more than 0")

if ip == 0 and url == 0:
    ip, url = 1, 1

ip_threads, url_threads = [], []

if ip != 0:
    with open("rules/threat_intel/malware_ip.txt") as f:
        file = f.readlines()
    for index in range(ip):
        thread = threading.Thread(target=ip_worker, args=(file, index,))
        ip_threads.append(thread)
        thread.start()

if url != 0:
    with open("rules/threat_intel/malware_domain.txt") as f:
        file = f.readlines()
    for index in range(url):
        thread = threading.Thread(target=url_worker, args=(file, index,))
        url_threads.append(thread)
        thread.start()


for t in ip_threads:
    t.join()

for t in url_threads:
    t.join()
