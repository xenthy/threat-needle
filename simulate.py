#!/usr/bin/env python3

import argparse
import random
import subprocess
import threading

import smtplib
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

def email_worker(index, attachment=None):
    send_from = "malicious@gmail.com"
    send_to = "drack@fisherman.ict"
    subject = "Simulation"
    text = "hey check the attached file and the link http://apll.org"
    server="47.254.229.14"

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(text))

    if attachment:
        with open(attachment, "rb") as file_obj:
            part = MIMEApplication(file_obj.read(), Name=basename(attachment))

        part['Content-Disposition'] = 'attachment; filename="%s"' % basename(attachment)
        msg.attach(part)

    smtp = smtplib.SMTP(server, 1337)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()

    print(f"[!] Phishing email[{index + 1}] sent")


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
parser.add_argument("--email", "-e",
                    default=0,
                    type=int,
                    dest="email_count",
                    help="number of malicious Emails to simulate (>= 0)")
parser.add_argument("--media", "-m",
                    default=0,
                    type=int,
                    dest="media_count",
                    help="number of malicious Media files to simulate (>= 0)")
args = parser.parse_args()

media, email, ip, url = args.media_count, args.email_count, args.ip_count, args.url_count

if ip < 0 and url < 0:
    parser.error("IP and URL count has to be more than 0")
if ip < 0:
    parser.error("IP count has to be more than 0")
if url < 0:
    parser.error("URL count has to be more than 0")
if email < 0:
    parser.error("Email count has to be more than 0")
if media < 0:
    parser.error("Media count has to be more than 0")

if ip == 0 and url == 0 and email == 0 and media == 0:
    media, email, ip, url = 1, 1, 1, 1

email_threads, ip_threads, url_threads = [], [], []

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

if email != 0:
    # attachment = "doggo.jpg"
    attachment = None
    for index in range(email):
        thread = threading.Thread(target=email_worker, args=(index,attachment,))
        email_threads.append(thread)
        thread.start()

if media != 0:

    pass

for t in ip_threads:
    t.join()

for t in url_threads:
    t.join()
    
for t in email_threads:
    t.join()
