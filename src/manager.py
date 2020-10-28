import threading
from multiprocessing import Pool
import tracemalloc
from pathlib import Path

from vault import Vault
from thread import Thread
from features import find_streams, extract_payload
from yara_process import Yara
from threat_intel import ThreatIntel
from carver import Carver
from config import SESSION_CACHE_PATH, SESSION_CACHING_INTERVAL

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

# GLOBAL
threat_intel = ThreatIntel()
threat_intel.threat_update()


def manager(event):
    """
    To be sent to the manager
    """
    Thread.set_name("main-manager-thread")

    # Load Yara rules recurively from the .yar files in the "rules" directory
    Yara.load_rules()

    session_yara_control = threading.Thread(target=bulk_manager,
                                            args=[event],
                                            daemon=True)
    carving_control = threading.Thread(target=carving_manager,
                                       args=[event],
                                       daemon=True)
    session_caching_thread = threading.Thread(target=session_caching,
                                              args=[event],
                                              daemon=True)
    memory_thread = threading.Thread(target=memory,
                                     args=[event],
                                     daemon=True)

    session_yara_control.start()
    carving_control.start()
    session_caching_thread.start()
    memory_thread.start()

    session_yara_control.join()
    carving_control.join()
    session_caching_thread.join()
    memory_thread.join()


def bulk_manager(event):
    """
    Manages session_yara() and threat()
    """
    Thread.set_name("bulk-manager-thread")
    while not Thread.get_interrupt():
        temp_plist = Vault.get_threading_plist()
        logger.info(f"{len(temp_plist)} packets processed [{Thread.name()}]")

        stream_dict = find_streams(temp_plist)
        Vault.add_session(stream_dict)

        session_yara_thread = threading.Thread(target=session_yara,
                                               args=[stream_dict],
                                               daemon=True)
        threat_thread = threading.Thread(target=threat, args=[temp_plist], daemon=True)

        session_yara_thread.start()
        threat_thread.start()

        all_sessions = Vault.get_session_headers()
        logger.info(f"{len(all_sessions)} total sessions [{Thread.name()}]")

        event.wait(timeout=5)


def session_yara(stream_dict):
    Thread.set_name("session-yara-thread")
    Yara.run(stream_dict)


def threat(temp_plist):
    Thread.set_name("threat-thread")
    threat_intel.run(temp_plist)


def carving_manager(event):
    """
    Manages Carver.carve_stream()
    """
    Thread.set_name("carving_manager-thread")
    while not Thread.get_interrupt():
        carving_thread = threading.Thread(target=Carver.carve_stream, daemon=True)
        carving_thread.start()

        event.wait(timeout=10)


def memory(event):
    Thread.set_name("memory-thread")

    while not Thread.get_interrupt():
        current, peak = tracemalloc.get_traced_memory()
        logger.info(f"Current: {current / 10**6}MB |" +
                    f"Peak: {peak / 10**6}MB [{Thread.name()}]")

        event.wait(timeout=5)  # 2 seconds


def session_caching(event):
    Thread.set_name("session-caching-thread")

    while not Thread.get_interrupt():

        sessions = Vault.get_sessions(reset=True)

        pool = Pool()
        pool.map(session_worker, sessions.items())

        pool.close()
        pool.join()

        logger.info(f"cached to local file [{Thread.name()}]")
        event.wait(timeout=SESSION_CACHING_INTERVAL)


def session_worker(obj):
    header, plist = obj
    if (payload := extract_payload(plist, pure=True)) is None:
        return

    header = header.replace(" ", "_").replace(":", "-")

    runtime_path = f"{SESSION_CACHE_PATH}/{Vault.get_runtime_name()}"
    file = Path(f"{runtime_path}/{header}")

    if file.is_file():
        with open(f"{runtime_path}/{header}", "ab+") as f:
            f.write(payload)
    else:
        with open(f"{runtime_path}/{header}", "wb+") as f:
            f.write(payload)


if __name__ == "__main__":
    pass
