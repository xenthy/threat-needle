import time
import tracemalloc
import threading
from os import mkdir, system, name
from app import app, socketio

from vault import Vault
from util import Util
from manager import manager
from thread import Thread
from escapy import Escapy

from config import SESSION_CACHE_PATH, SESSION_CACHING_INTERVAL

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


def mapping(e):
    while not Thread.get_interrupt():
        system("cls") if name == "nt" else system("clear")
        print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}"
                        for key, count in Vault.get_mapping().items()))
        e.wait(timeout=10)


def main():
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

    """ MENU """
    info_data = [f"{RED}Sniffer is running but not saving anything locally{RESET}",
                 f"{GREEN}Sniffer is running saving packets locally{RESET}"]
    option = ["Type \"start\" to start saving: ",
              "Type \"stop\" to stop saving: "]

    while True:
        print(info_data[0 if not Vault.get_saving() else 1], end="\n")
        user_input = input(option[0 if not Vault.get_saving() else 1])
        if Vault.get_saving() == False and user_input == "start":
            Util.start_saving()

        elif Vault.get_saving() == True and user_input == "stop":
            Util.stop_saving()

        elif user_input == "q":
            break

        else:
            print(f"{YELLOW}Invalid option{RESET}", end="\n\n")

    """ SAVE TO FILE IF PROGRAM ENDED AND SAVING IS TRUE """
    if Vault.get_saving() == True:
        Util.stop_saving()

    # interrupt threads
    Thread.set_interrupt(True)
    event.set()
    Escapy.stop()

    # wait for threads to complete
    manager_thread.join()


def flask_app():
    socketio.run(app)


if __name__ == "__main__":
    # start of logging
    logger.info("__INIT__")

    # set thread name
    Thread.set_name("main-thread")

    # track memory usage
    tracemalloc.start()

    # start flask app
    flask_thread = threading.Thread(target=flask_app, daemon=True)
    flask_thread.start()
    time.sleep(0.5)  # allow flask to init first

    # init main threads
    main()

tracemalloc.stop()
logger.info("__EOF__")
