from vault import Vault
from thread import Thread

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


def manager(lock, e):
    """
    To be sent to the manager
    """
    Thread.set_name("manager-thread")

    while not Vault.get_interrupt():
        # lock.acquire()  # protect critical section
        # temp_plist = Vault.get_threading_plist()
        logger.info(f"{len(Vault.get_threading_plist())} packets processed [{Thread.name()}]")
        # Vault.add_count(len(temp_plist))
        # lock.release()

        e.wait(timeout=2)  # 5 seconds


if __name__ == "__main__":
    pass
