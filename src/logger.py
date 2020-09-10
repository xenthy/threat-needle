import logging
from colour import CYAN, RESET

LOG_FILE = "logs/program.log"
FORMATTER = "%(asctime)s:%(msecs)03d:[%(levelname)s]:%(name)s: %(message)s"
TIMESTAMP = "%b %d  %Y %H:%M:%S"

with open(LOG_FILE, "w+") as f:
    pass

print("\n", CYAN, f"Log in {LOG_FILE}", RESET)
