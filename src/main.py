from vault import Vault
from util import Util

from app import app, socketio

from manager import manager
from thread import Thread
import tracemalloc
import threading
import time

from escapy import Escapy
from collections import Counter

from os import mkdir

from features import extract_payload

from config import SESSION_CACHE_PATH, SESSION_CACHING_INTERVAL

from colour import GREEN, RED, YELLOW, RESET
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.info("__INIT__")

# Create a Packet Counter
packet_counts = Counter()

""" MEMORY OPTIMIZING """
tracemalloc.start()

""" THREADING EVENT """
e = threading.Event()


def custom_action(packet):

    Vault.plist_append(packet)

    # Create tuple of Src/Dst in sorted order | this is for debugging can delete
    # try:
    #     key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    #     packet_counts.update([key])
    #     logger.debug(f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}")
    # except AttributeError:
    #     key = tuple(sorted([packet[0][0].src, packet[0][0].dst]))
    #     packet_counts.update([key])
    #     logger.debug(f"Packet #{sum(packet_counts.values())}: {packet[0][0].src} ==> {packet[0][0].dst}")


def main():
    """ INIT VARIABLES """
    Thread.set_name("main-thread")

    """ SET RUNTIME NAME """
    Vault.set_runtime_name(Util.datetime_to_string())

    """ CREATE RUNTIME DIRECTORY """
    mkdir(f"{SESSION_CACHE_PATH}/{Vault.get_runtime_name()}")

    """ THREADING """
    Thread.set_interrupt(False)
    lock = threading.Lock()
    manager_thread = threading.Thread(target=manager, args=(lock, e,), daemon=True)

    """ INDEFINITE SNIFFING """
    Escapy.async_sniff(custom_action)
    manager_thread.start()

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

    Thread.set_interrupt(True)
    Escapy.stop()
    e.set()
    manager_thread.join()

    """ MAPPING: Print out packet count per A <--> Z address pair """
    # logger.info("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))

    """ DISSECT PACKETS """
    # for packet in cap:
    #     converted = Util.convert_packet(packet)
    #     logger.info(pformat((converted)))


def flask_app():
    socketio.run(app)


if __name__ == "__main__":
    flask_thread = threading.Thread(target=flask_app, daemon=True)
    flask_thread.start()
    time.sleep(0.5)  # allow flask to init first
    main()

logger.info("__EOF__")
tracemalloc.stop()
