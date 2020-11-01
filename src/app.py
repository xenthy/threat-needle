from os.path import isfile, join
from os import listdir

from threading import Thread, Event

from flask import Flask, render_template, request, redirect, send_file, jsonify
from flask_socketio import SocketIO

from util import Util
from vault import Vault

from yara_create import Rule, YaraFiles

from config import CAP_PATH, SESSION_CACHE_PATH, CARVED_DIR

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP, LOG_LEVEL
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


app = Flask(__name__)
app.config["SECRET_KEY"] = "secret!"
app.config["DEBUG"] = False
app.config["SERVER_NAME"] = "127.0.0.1:8000"

socketio = SocketIO(app, async_mode=None)
thread = Thread()
thread_stop_event = Event()

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

COMMON_PROTOCOLS = {"80": "HTTP",
                    "443": "HTTPS",
                    "21": "FTP",
                    "22": "SSH",
                    "23": "Telnet",
                    "53": "DNS"}


def get_formatted_header(prot_type):
    '''Receives either TCP or UDP to return actual header '''
    global COMMON_PROTOCOLS
    sessions = {}
    for session_header in Vault.get_session_headers():
        if prot_type in session_header:
            header_list = session_header[4:].replace('_', '-').split('-')
            for i in range(1, 4, 2):
                if header_list[i] in COMMON_PROTOCOLS:
                    formatted_header = COMMON_PROTOCOLS[header_list[i]] +\
                    " " + " ".join(header_list)
                    sessions[formatted_header] = session_header
                    break
                if i == 3:
                    sessions[session_header] = session_header
    return sessions


def get_data():
    ''' repeatedly send updated packet count data to socket'''
    while not thread_stop_event.isSet():
        socketio.emit("data", {"total_packets": Vault.get_total_packet_count(),
                               "total_streams": len(Vault.get_session_headers()),
                               "total_flagged": len(Vault.get_flagged())}, namespace="/socket")
        socketio.sleep(0.01)


@app.route("/", methods=["POST", "GET"])
def index():
    ''' If method == GET , returns HTML Page 
        If method == POST, returns data for protocl piechart
    '''
    if request.method != "POST":
        return render_template("index.html", status=Vault.get_saving())

    global COMMON_PROTOCOLS
    protocol_dict = {}

    for header in Vault.get_session_headers():
        if 'TCP' in header or 'UDP' in header:
            header_list = header[4:].replace('_', '-').split('-')
            if header_list[1] in COMMON_PROTOCOLS or header_list[3] in COMMON_PROTOCOLS:
                try:
                    prot = COMMON_PROTOCOLS[header_list[1]]
                except Exception:
                    prot = COMMON_PROTOCOLS[header_list[3]]
                protocol_dict[prot] = protocol_dict[prot] + 1 if prot in protocol_dict else 1
            else:
                protocol_dict["Other"] = protocol_dict["Other"] + 1 if "Other" in protocol_dict else 1

        else:
            protocol_dict["Other"] = protocol_dict["Other"] + 1 if "Other" in protocol_dict else 1
    return jsonify(protocol_dict)

@app.route("/network", methods=["POST", "GET"])
def network():
    ''' If method == GET , returns network mapping page 
        If method == POST, returns mapping_dict,ip_list,mal_list for network mapping
    '''
    if request.method == "POST":
        mal_list = []
        mapping, ip_list = Vault.get_mapping()
        flagged_dict = Vault.get_flagged()
        for _, obj in flagged_dict.items():
            if 'endpoint' in obj.identifier:
                for match in obj.strings:
                    mal_list.append(match[2].decode('utf-8'))

        return jsonify(mapping, ip_list, mal_list)

    return render_template("network.html", status=Vault.get_saving(), data=Vault.get_mapping())


@app.route("/viewfile")
def savefile():
    ''' returns viewfile page with all the saved files '''
    pcap_files = [f for f in listdir(CAP_PATH) if
                  isfile(join(CAP_PATH, f)) if f[-4:] == ".cap"]

    carved_files = [f for f in listdir(CARVED_DIR) if
                    isfile(join(CARVED_DIR, f))]
    return render_template("viewfile.html", pcap_files=pcap_files,
                           carved_files=carved_files, status=Vault.get_saving())


@app.route("/viewfile/<file_name>")
def download(file_name):
    '''returns a file for user to download'''
    pcap_files = [f for f in listdir(CAP_PATH) if isfile(
        join(CAP_PATH, f)) if f[-4:] == ".cap"]
    carved_files = [f for f in listdir(CARVED_DIR) if isfile(
        join(CARVED_DIR, f))]
    if file_name in pcap_files:
        return send_file(f"../{CAP_PATH}/{pcap_files[pcap_files.index(file_name)]}", as_attachment=True)
    if file_name in carved_files:
        return send_file(f"../{CARVED_DIR}/{carved_files[carved_files.index(file_name)]}", as_attachment=True)
    return "Error"


@app.route("/viewtcp", methods=["POST", "GET"])
def view_tcp():
    '''returns TCP stream page'''
    tcp_sessions = get_formatted_header('TCP')
    payload = None
    return render_template("viewtcp.html", tcp_sessions=tcp_sessions, payload=payload, status=Vault.get_saving())


@app.route("/viewudp", methods=["POST", "GET"])
def view_udp():
    '''returns UDP stream page'''
    udp_sessions = get_formatted_header('UDP')
    payload = None
    return render_template("viewudp.html", udp_sessions=udp_sessions, payload=payload, status=Vault.get_saving())


@app.route("/viewarp")
def view_arp():
    '''returns arp page'''
    arp_sessions = [session for session in Vault.get_session_headers() if 'ARP' in session]
    return render_template("viewarp.html", arp_sessions=arp_sessions, status=Vault.get_saving())


@app.route("/stream/<file_name>")
def downloadstream(file_name):
    '''returns binary file of a stream'''
    session = get_formatted_header('TCP')
    return send_file(f"../{SESSION_CACHE_PATH}/{Vault.get_runtime_name()}/{session[file_name]}", as_attachment=True)


@app.route("/save", methods=["POST"])
def save():
    '''Called by UI to start capturing packets'''
    saving = request.json["data"].strip()
    if saving == "Save":
        Util.start_saving()
    else:
        Util.stop_saving()
    return f"sucessful operation: {saving}"


@app.route("/reset", methods=["POST"])
def reset():
    '''Called by UI to reset packet capture'''
    Vault.refresh()
    return f"Sucessfully Refreshed"


@app.route("/addrule", methods=["POST", "GET"])
def add_rule():
    ''' If method == GET , returns addrule page
        If method == POST, creates yara rule , and return back to page
    '''
    if request.method == "POST":
        filename = request.form["filename"]
        author = request.form["author"]
        rule_name = request.form["rulename"]
        tag = request.form["tag"]
        description = request.form["description"]
        strings = request.form["strings"]
        condition = request.form["condition"]

        # save to yara config
        Rule.create_rule(filename, author, rule_name, tag, description, strings, condition)
        return redirect(request.url)
    return render_template("addrule.html", status=Vault.get_saving())


@app.route("/flagged", methods=["POST", "GET"])
def flagged():
    ''' If method == GET , returns flagged page
        If method == POST, returns payload of flagged packet
    '''
    if request.method == "POST":
        key = request.json["data"].strip()
        flagged_dict = Vault.get_flagged()

        flagged_obj = flagged_dict[key]
        if flagged_obj.identifier == "payload":
            return flagged_obj.payload

        strings_list = []
        for i in range(len(flagged_obj.strings)):
            strings_list.append((flagged_obj.strings[i][0], flagged_obj.strings[i][0],
                                 flagged_obj.strings[i][2].decode('utf-8')))

        return jsonify(strings_list)
    return render_template("flagged.html", flagged_packets=Vault.get_flagged(), status=Vault.get_saving())


@app.route("/rules", methods=["POST", "GET"])
def yara_rules():
    ''' If method == GET , returns rule page
        If method == POST, returns content of selected rule file
    '''
    threat_rules = YaraFiles.get_threat_rules()
    mal_rules = YaraFiles.get_mal_rules()
    custom_rules = YaraFiles.get_custom_rules()

    if request.method == "POST":
        file_name = request.data.decode('utf-8')
        if file_name in threat_rules:
            return threat_rules[file_name]
        elif file_name in mal_rules:
            return mal_rules[file_name]
        elif file_name in custom_rules:
            return custom_rules[file_name]

        return "Yara File Not Found"

    return render_template("viewrules.html", threat_rules=threat_rules.keys(), mal_rules=mal_rules.keys(), custom_rules=custom_rules.keys(), status=Vault.get_saving())


@app.route("/logs", methods=["POST", "GET"])
def logs():
    ''' If method == GET , returns logs page
        If method == POST, returns content of selected rule file
    '''
    if request.method == "POST":
        message = Util.tail(LOG_FILE, 20)
        return message

    return render_template("logs.html", status=Vault.get_saving())


@socketio.on("connect", namespace="/socket")
def connect():
    ''' Initiates socket to allow polling packet count data'''
    global thread
    logger.debug("client connected")

    if not thread.is_alive():
        logger.info("starting socket thread")
        thread = socketio.start_background_task(get_data)


@socketio.on("disconnect", namespace="/socket")
def disconnect():
    '''disconnects'''
    logger.debug("client disconnected")


if __name__ == "__main__":
    socketio.run(app)
