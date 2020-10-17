from flask import Flask, render_template, url_for, copy_current_request_context, request, redirect
from flask_socketio import SocketIO, emit
from time import sleep
from threading import Thread, Event
import random
from util import Util
from vault import Vault
from os.path import isfile, join
from os import listdir
from config import CAP_PATH , SESSION_CACHE_PATH

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = False
app.config['SERVER_NAME'] = '127.0.0.1:8000'

socketio = SocketIO(app, async_mode=None)
thread = Thread()
thread_stop_event = Event()

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


total_flagged = 0

def get_data():
    global total_flagged

    while not thread_stop_event.isSet():
        # total_streams += int(random.random() * 100)
        # total_flagged += int(random.random() * 100)

        socketio.emit(
            'data', {'total_packets': Vault.get_total_packet_count(), 'total_streams': len(Vault.get_session_headers()), 'total_flagged': total_flagged}, namespace='/test')

        socketio.sleep(0.01)


@app.route('/')
def index():
    return render_template('index.html')



@app.route('/viewfile')
def savefile():
    onlyfiles = [f for f in listdir(CAP_PATH) if isfile(join(CAP_PATH, f)) if f[-4:] == '.cap']
    return render_template('viewfile.html', files=onlyfiles)


@app.route('/viewtcp', methods=['POST','GET'])
def view_tcp():

    tcp_sessions=[session_header for session_header in Vault.get_session_headers() if 'TCP' in session_header]

    payload = None
    if request.method == 'POST':
        header = request.form['session']
        header = header.replace(' ','_').replace(':','-')
        path = f'{SESSION_CACHE_PATH}/{Vault.get_runtime_name()}/{header}'
        try:
            with open(path, "rb") as f:
                payload = f.read()           
            #logger.info(payload)
            payload = payload.decode('utf-8')
        except Exception:
            payload = None
    return render_template('viewsession.html',tcp_sessions=tcp_sessions, payload=payload)

@app.route('/viewudp')
def view_udp():
    udp_sessions=[session_header for session_header in Vault.get_session_headers() if 'UDP' in session_header]
    return render_template('viewsession.html',udp_sessions=udp_sessions)
    

@app.route('/save', methods=['POST'])
def save():
    saving = request.json['data'].strip()
    if saving == 'Save':
        Util.start_saving()
    else:
        Util.stop_saving()
    return f"sucessful operation: {saving}"


@app.route('/addrule', methods=['POST','GET'])
def add_rule():
    if request.method == 'POST':
        author = request.form['author']
        rule_name = request.form['rulename']
        description = request.form['description']
        strings = request.form['strings']
        condition = request.form['condition']

        #save to yara config
        print(author,rule_name,description,strings,condition)
        
        return redirect(request.url)
    else:
        return render_template('addrule.html')


@socketio.on('connect', namespace='/test')
def test_connect():
    # need visibility of the global thread object
    global thread
    logger.info("client connected")

    # Start the random number generator thread only if the thread has not been started before.
    if not thread.isAlive():
        logger.info("starting socket thread")
        thread = socketio.start_background_task(get_data)


@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    logger.info('client disconnected')


if __name__ == "__main__":
    socketio.run(app)
