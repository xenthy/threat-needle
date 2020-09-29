from flask import Flask, render_template, url_for, copy_current_request_context
from flask_socketio import SocketIO, emit
from time import sleep
from threading import Thread, Event
import random
import logging
from vault import Vault
from os.path import isfile, join
from os import listdir
from config import CAP_PATH


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
packet = [
    {'src': '192.168.2.3', 'dst': '127.2.4.5', 'prot': '80', 'desc': '1'},
    {'src': '192.168.1.2', 'dst': '127.2.4.5', 'prot': '80', 'desc': '2'},
    {'src': '192.168.2.3', 'dst': '127.20.4.5', 'prot': '333', 'desc': '3'},
    {'src': '192.148.2.3', 'dst': '127.20.4.5', 'prot': '80', 'desc': '4'}
]


def get_data():
    global total_flagged

    while not thread_stop_event.isSet():
        # total_streams += int(random.random() * 100)
        # total_flagged += int(random.random() * 100)

        socketio.emit(
            'data', {'total_packets': Vault.get_total_packet_count(), 'total_streams': len(Vault.get_sessions()), 'total_flagged': total_flagged}, namespace='/test')

        socketio.sleep(0.01)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/viewfile')
def savefile():
    onlyfiles = [f for f in listdir(CAP_PATH) if isfile(join(CAP_PATH, f)) if f[-4:]=='.cap']
    return render_template('viewfile.html', files = onlyfiles)


@socketio.on('connect', namespace='/test')
def test_connect():
    # need visibility of the global thread object
    global thread
    print('Client connected')

    # Start the random number generator thread only if the thread has not been started before.
    if not thread.isAlive():
        print("Starting Thread")
        thread = socketio.start_background_task(get_data)


@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


if __name__ == "__main__":
    socketio.run(app)
