import tracemalloc
from os import listdir
from os.path import isfile, join

from multiprocessing import Pool
from pathlib import Path

from vault import Vault
from thread import thread, Thread
from features import find_streams, extract_payload
from yara_process import Yara
from threat_intel import ThreatIntel
from carver import Carver
from config import SESSION_CACHE_PATH, SESSION_CACHING_INTERVAL,\
    BULK_MANAGER_INTERVAL, MEMORY_WATCHDOG_INTERVAL, CARVING_INTERVAL
    
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP, LOG_LEVEL
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

# GLOBAL
threat_intel = ThreatIntel()
threat_intel.threat_update()


@thread(daemon=True)
def manager(event):
    """
    Facilitates and creation of sub-threads
    """

    # Load Yara rules recursively from the .yar files in the "rules" directory
    Yara.load_rules()

    # start threads
    session_yara_control = bulk_manager(event)
    session_caching_thread = session_caching(event)
    memory_thread = memory(event)

    # wait for threads to complete
    session_yara_control.join()
    session_caching_thread.join()
    memory_thread.join()

    logger.info(f"All sub-threads terminated [{Thread.name()}]")


@thread(daemon=True)
def bulk_manager(event):
    """
    Manages session_yara() and threat()
    """
    while not Thread.get_interrupt():
        temp_plist = Vault.get_threading_plist()
        logger.info(f"{len(temp_plist)} packets processed [{Thread.name()}]")

        stream_dict = find_streams(temp_plist)
        Vault.add_session(stream_dict)

        session_yara(stream_dict)
        threat(temp_plist)

        all_sessions = Vault.get_session_headers()
        logger.info(f"{len(all_sessions)} total sessions [{Thread.name()}]")

        event.wait(timeout=BULK_MANAGER_INTERVAL)
    logger.info(f"Terminated [{Thread.name()}]")


@thread(daemon=True)
def session_yara(stream_dict):
    Yara.run(stream_dict)


@thread(daemon=True)
def threat(temp_plist):
    threat_intel.run(temp_plist)


@thread(daemon=True)
def memory(event):
    while not Thread.get_interrupt():
        current, peak = tracemalloc.get_traced_memory()
        logger.info(f"Current: {current / 10**6}MB | " +
                    f"Peak: {peak / 10**6}MB [{Thread.name()}]")

        event.wait(timeout=MEMORY_WATCHDOG_INTERVAL)
    logger.info(f"Terminated [{Thread.name()}]")


@thread(daemon=True)
def session_caching(event):
    while not Thread.get_interrupt():
        runtime_path = f"{SESSION_CACHE_PATH}/{Vault.get_runtime_name()}"
        cache_files = [f for f in listdir(runtime_path) if isfile(join(runtime_path, f))]
        sessions = Vault.get_sessions(reset=True)

        for header, plist in sessions.items():
            if (payload := extract_payload(plist, pure=True)) is None:
                continue
            header = header.replace(" ", "_").replace(":", "-")
            if header in cache_files:
                with open(f"{runtime_path}/{header}", "ab+") as file:
                    # f.seek(0, 2)
                    file.write(payload)
            else:
                with open(f"{runtime_path}/{header}", "wb+") as file:
                    file.write(payload)

        logger.info(f"Cached to .cache [{Thread.name()}]")
        event.wait(timeout=SESSION_CACHING_INTERVAL)
    logger.info(f"Terminated [{Thread.name()}]")


@thread(daemon=True)
def session_caching_mp(event):
    while not Thread.get_interrupt():

        sessions = Vault.get_sessions(reset=True)

        pool = Pool()
        pool.map(session_worker, sessions.items())

        pool.close()
        pool.join()

        logger.info(f"cached to local file [{Thread.name()}]")
        event.wait(timeout=SESSION_CACHING_INTERVAL)
    logger.info(f"Terminated [{Thread.name()}]")


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
