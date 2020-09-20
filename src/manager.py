from vault import Vault
import threading
from thread import Thread
from features import find_streams
from yara_process import Yara
from threat_intel import ThreatIntel

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

""" GLOBAL """
yar = Yara()
threat_intel = ThreatIntel()


def manager(lock, e):
    """
    To be sent to the manager
    """
    Thread.set_name("manager-thread")

    while not Vault.get_interrupt():
        # lock.acquire()  # protect critical section

        temp_plist = Vault.get_threading_plist()
        logger.info(f"{len(temp_plist)} packets processed [{Thread.name()}]")

        session_yara_thread = threading.Thread(target=session_yara, args=[temp_plist], daemon=True)
        threat_thread = threading.Thread(target=session_yara, args=[temp_plist], daemon=True)

        session_yara_thread.start()
        threat_thread.start()

        # lock.release()

        e.wait(timeout=2)  # 5 seconds


def session_yara(temp_plist):
    """ SESSION & YARA """
    # session_yara_thread.start()
    stream_dict = find_streams(temp_plist)

    yar.run(stream_dict)

    Vault.add_session(stream_dict)


def threat(temp_plist):
    # threat_intel.run(temp_plist)
    pass


if __name__ == "__main__":
    pass
