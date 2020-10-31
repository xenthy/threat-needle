"""
Entry point of the application
"""

import time
import tracemalloc
import threading
from os import mkdir
from app import app, socketio

from vault import Vault
from util import Util
from manager import manager
from thread import thread, Thread
from escapy import Escapy

from config import SESSION_CACHE_PATH

from colour import GREEN, RED, YELLOW, RESET
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


def custom_action(packet):
    Vault.plist_append(packet)
    Vault.update_mapping(packet)


def main():
    """
    Main method to control the program flow
    """
    # set runtime name
    Vault.set_runtime_name(Util.datetime_to_string())

    # create runtime directory
    mkdir(f"{SESSION_CACHE_PATH}/{Vault.get_runtime_name()}")

    # set up threading
    Thread.set_interrupt(False)
    event = threading.Event()

    # start threads
    manager_thread = manager(event)
    Escapy.async_sniff(custom_action)

    # menu
    info_data = [f"{RED}Sniffer is running but not saving anything locally{RESET}",
                 f"{GREEN}Sniffer is running saving packets locally{RESET}"]
    option = ["Type \"start\" to start saving: ",
              "Type \"stop\" to stop saving: "]

    while True:
        print(info_data[0 if not Vault.get_saving() else 1], end="\n")
        print(f"Dashboard: {YELLOW}http://127.0.0.1:8000{RESET} | \'q\' to stop")
        user_input = input(option[0 if not Vault.get_saving() else 1])
        if not Vault.get_saving() and user_input == "start":
            Util.start_saving()

        elif Vault.get_saving() and user_input == "stop":
            Util.stop_saving()

        elif user_input == "q":
            break

        else:
            print(f"{YELLOW}Invalid option{RESET}", end="\n\n")

    # SAVE TO FILE IF PROGRAM ENDED AND SAVING IS TRUE
    if Vault.get_saving():
        Util.stop_saving()

    # interrupt threads
    Thread.set_interrupt(True)
    event.set()
    Escapy.stop()

    # wait for threads to complete
    manager_thread.join()


@thread(daemon=True)
def flask_app():
    """
    Run the Flask Application on a separate thread
    """
    socketio.run(app)


if __name__ == "__main__":
    # start of logging
    logger.info("__INIT__")

    # set thread name
    threading.current_thread().setName("main-thread")

    # track memory usage
    tracemalloc.start()

    # start flask app
    flask_app()
    time.sleep(0.5)  # allow flask to init first

    # init main threads
    main()

tracemalloc.stop()
logger.info("__EOF__")
