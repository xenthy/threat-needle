from vault import Vault
from util import Util

from app import app, socketio

import time
from manager import manager
from thread import Thread
import tracemalloc
import threading

from sniffer import Sniffer
from collections import Counter

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


def memory():
    Thread.set_name("memory-thread")

    while not Vault.get_interrupt():
        current, peak = tracemalloc.get_traced_memory()
        logger.info(
            f"Current: {current / 10**6}MB | Peak: {peak / 10**6}MB [{Thread.name()}]")

        e.wait(timeout=5)  # 2 seconds


def main():
    """ INIT VARIABLES """
    Thread.set_name("main-thread")
    file_name = None

    """ THREADING """
    Vault.set_interrupt(False)
    lock = threading.Lock()
    memory_thread = threading.Thread(target=memory, daemon=True)
    manager_thread = threading.Thread(
        target=manager, args=(lock, e,), daemon=True)

    """ INDEFINITE SNIFFING """
    Sniffer.start(custom_action)
    memory_thread.start()
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
            logger.info("Initalising saving to file...")
            file_name = str(time.ctime(time.time())).replace(":", "-")
            Vault.set_saving(True)

        elif Vault.get_saving() == True and user_input == "stop":
            logger.info("Terminating saving to file...")
            Vault.set_saving(False)

            """ SAVING TO .CAP """
            cap = Vault.get_saving_plist()
            Util.save_cap(file_name, cap)

        elif user_input == "q":
            break
        else:
            print(f"{YELLOW}Invalid option{RESET}", end="\n\n")

    """ SAVE TO FILE IF PROGRAM ENDED AND SAVING IS TRUE """
    if Vault.get_saving() == True:
        logger.info("Terminating saving to file...")
        Vault.set_saving(False)

        """ SAVING TO .CAP """
        cap = Vault.get_saving_plist()
        Util.save_cap(file_name, cap)

    Vault.set_interrupt(True)
    Sniffer.stop()
    e.set()
    memory_thread.join()
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
    main()

logger.info("__EOF__")
tracemalloc.stop()
