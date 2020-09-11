from sniffer import init_sniffer

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.info("__INIT__")


def main():
    print("Nothing for now...")
    # init_sniffer()


if __name__ == "__main__":
    main()
    logger.info("__EOF__")
