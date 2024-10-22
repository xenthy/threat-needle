from config import LOGGER_PATH
import logging
from colour import CYAN, RESET

LOG_FILE = f"{LOGGER_PATH}program.log"
FORMATTER = "%(asctime)s:%(msecs)03d:[%(levelname)s]:%(name)s: %(message)s"
TIMESTAMP = "%b %d  %Y %H:%M:%S"
LOG_LEVEL = logging.INFO

with open(LOG_FILE, "w+") as f:
    pass

print(f"\n{CYAN}Log in {LOG_FILE}{RESET}")
