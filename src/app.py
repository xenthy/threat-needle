from flask import Flask, render_template, url_for, copy_current_request_context, request, redirect
from flask_socketio import SocketIO, emit
from time import sleep
from threading import Thread, Event
import random
from util import Util
from vault import Vault
from os.path import isfile, join
from os import listdir
from config import CAP_PATH, SESSION_CACHE_PATH
from yara_create import create_rule 

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


total_flagged = 0


def open_file(header, sessions):
    path = f"{SESSION_CACHE_PATH}/{Vault.get_runtime_name()}/{sessions[header].replace(' ', '_').replace(':','-')}"

    try:
        with open(path, "rb") as f:
            payload = f.read()

        payload = payload.decode("utf-8")
    except Exception as e:
        logger.warning(format(e))
        payload = None
    return payload


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
            header_list = session_header[4:].replace(' ' , ':').split(':')
            for index in range(1, 4, 2):
                if header_list[index] in common_protocols:
                    formatted_header = common_protocols[header_list[index]] + " " + " ".join(header_list)
                    sessions[formatted_header] = session_header
                    break

                if index == 3:
                    sessions[session_header] = session_header
    return sessions


def get_data():
    global total_flagged

    while not thread_stop_event.isSet():
        # total_streams += int(random.random() * 100)
        # total_flagged += int(random.random() * 100)

        socketio.emit(
            "data", {"total_packets": Vault.get_total_packet_count(), "total_streams": len(Vault.get_session_headers()), "total_flagged": total_flagged}, namespace="/test")

        socketio.sleep(0.01)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/viewfile")
def savefile():
    onlyfiles = [f for f in listdir(CAP_PATH) if isfile(
        join(CAP_PATH, f)) if f[-4:] == ".cap"]
    return render_template("viewfile.html", files=onlyfiles)


@app.route("/viewtcp", methods=["POST", "GET"])
def view_tcp():

    tcp_sessions = get_formatted_header('TCP')
    payload = None
    if request.method == "POST":
        header = request.form["session"]
        payload = open_file(header, tcp_sessions)
    return render_template("viewtcp.html", tcp_sessions=tcp_sessions, payload=payload)


@app.route("/viewudp", methods=["POST", "GET"])
def view_udp():
    udp_sessions =get_formatted_header('UDP')
    payload = None
    if request.method == "POST":
        header = request.form["session"]
        payload = open_file(header, udp_sessions)
    return render_template("viewudp.html", udp_sessions=udp_sessions, payload=payload)


@app.route("/viewarp")
def view_arp():
    arp_sessions =[session for session in Vault.get_session_headers() if 'ARP' in session]

    return render_template("viewarp.html", arp_sessions=arp_sessions)

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
        create_rule(filename, author, rule_name, tag, description, strings, condition)
        return redirect(request.url)
    else:
        return render_template("addrule.html")


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
