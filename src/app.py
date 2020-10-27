from flask import Flask, render_template, url_for, copy_current_request_context, request, redirect ,jsonify , send_file
from flask_socketio import SocketIO, emit
from time import sleep
from threading import Thread, Event
import random
from util import Util
from vault import Vault
from os.path import isfile, join
from os import listdir ,name as os_name

from config import CAP_PATH, SESSION_CACHE_PATH, CARVED_DIR
from yara_create import Rule

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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


# def open_file(header,sessions):
#     path = f"{SESSION_CACHE_PATH}/{Vault.get_runtime_name()}/{sessions[header].replace(' ', '_').replace(':','-')}"
    
#     try:
#         with open(path, "rb") as f:
#             payload = f.read()

#         payload = payload.decode("utf-8")
#     except Exception as e:
#         logger.warning(format(e))
#         payload = None
#     return payload

def get_formatted_header(prot_type):
    common_protocols = {"80": "HTTP",
                        "443": "HTTPS",
                        "21": "FTP",
                        "22": "SSH",
                        "23": "Telnet",
                        "53": "DNS"
                        }
    sessions={}
    for session_header in Vault.get_session_headers():
        if prot_type in session_header:
            header_list = session_header[4:].replace('_' , '-').split('-')
            for index in range(1, 4, 2):
                if header_list[index] in common_protocols:
                    formatted_header = common_protocols[header_list[index]] + " " + " ".join(header_list)
                    sessions[formatted_header] = session_header
                    break

                if index == 3:
                    sessions[session_header] = session_header
    return sessions



def get_data():

    while not thread_stop_event.isSet():
        # total_streams += int(random.random() * 100)
        # total_flagged += int(random.random() * 100)

        socketio.emit(
            "data", {"total_packets": Vault.get_total_packet_count(), "total_streams": len(Vault.get_session_headers()), "total_flagged": len(Vault.get_flagged())}, namespace="/test")
        socketio.sleep(0.01)


@app.route("/")
def index():
    return render_template("index.html", status=Vault.get_saving())


@app.route("/viewfile")
def savefile():
    pcap_files = [f for f in listdir(CAP_PATH) if isfile(
        join(CAP_PATH, f)) if f[-4:] == ".cap"]
    
    carved_files = [f for f in listdir(CARVED_DIR) if isfile(
        join(CARVED_DIR, f))]

    return render_template("viewfile.html", pcap_files=pcap_files, carved_files=carved_files , status=Vault.get_saving())

@app.route("/viewfile/<file_name>")
def download(file_name):
    
    pcap_files = [f for f in listdir(CAP_PATH) if isfile(
        join(CAP_PATH, f)) if f[-4:] == ".cap"]
    
    carved_files = [f for f in listdir(CARVED_DIR) if isfile(
        join(CARVED_DIR, f))]
        
    if file_name in pcap_files and os_name == "nt":
        return send_file(join("..\\cap\\",pcap_files[pcap_files.index(file_name)]), as_attachment=True)
    elif file_name in carved_files and os_name == "nt":
        return send_file(join("..\\carved\\",carved_files[carved_files.index(file_name)]), as_attachment=True)
    elif file_name in pcap_files and os_name != "nt":
        return send_file(join(CAP_PATH,pcap_files[pcap_files.index(file_name)]), as_attachment=True)
    elif file_name in carved_files and os_name != "nt":
        return send_file(join(CARVED_DIR,carved_files[carved_files.index(file_name)]), as_attachment=True)
    else:
        return "Error"


@app.route("/viewtcp", methods=["POST", "GET"])
def view_tcp():
    tcp_sessions= get_formatted_header('TCP')
    payload = None
    return render_template("viewtcp.html", tcp_sessions=tcp_sessions, payload=payload , status=Vault.get_saving())

@app.route("/viewudp", methods=["POST", "GET"])
def view_udp():
    udp_sessions = get_formatted_header('UDP')
    payload = None
    return render_template("viewudp.html", udp_sessions=udp_sessions, payload=payload , status=Vault.get_saving())


@app.route("/viewarp")
def view_arp():
    arp_sessions =[session for session in Vault.get_session_headers() if 'ARP' in session]

    return render_template("viewarp.html", arp_sessions=arp_sessions , status=Vault.get_saving())



@app.route("/stream/<file_name>")
def downloadstream(file_name):
    s = get_formatted_header('TCP')
    if os_name == "nt":
        return send_file(join("..\\.cache\\",Vault.get_runtime_name(),s[file_name]), as_attachment=True)
    else:
        return send_file(join(SESSION_CACHE_PATH,Vault.get_runtime_name(),s[file_name]), as_attachment=True)


@app.route("/save", methods=["POST"])
def save():
    saving = request.json["data"].strip()
    if saving == "Save":
        Util.start_saving()
    else:
        Util.stop_saving()
    return f"sucessful operation: {saving}"


@app.route("/addrule", methods=["POST", "GET"])
def add_rule():
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
    else:
        return render_template("addrule.html", status=Vault.get_saving())


@app.route("/flagged", methods=["POST", "GET"])
def flagged():
    if request.method == "POST":
        key = request.json["data"].strip()
        flagged_dict = Vault.get_flagged()

        flagged_obj = flagged_dict[key]
        if flagged_obj.identifier == "payload":
            return flagged_obj.payload
        else:
            flagged_obj.packet[0][1].src
            flagged_obj.packet[0][1].dst
            return flagged_obj.packet[0][1]
    else:
        return render_template("flagged.html" , flagged_packets=Vault.get_flagged() , status=Vault.get_saving())

@socketio.on("connect", namespace="/test")
def test_connect():
    # need visibility of the global thread object
    global thread
    logger.info("client connected")

    # Start the random number generator thread only if the thread has not been started before.
    if not thread.isAlive():
        logger.info("starting socket thread")
        thread = socketio.start_background_task(get_data)

@socketio.on("disconnect", namespace="/test")
def test_disconnect():
    logger.info("client disconnected")


if __name__ == "__main__":
    socketio.run(app)
