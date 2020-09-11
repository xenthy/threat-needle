from sniffer import init_sniffer

from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.info("__INIT__")


def tcp_dump():
    import subprocess as sub

    p = sub.Popen(('sudo', 'tcpdump', '-l'), stdout=sub.PIPE)
    for row in iter(p.stdout.readline, b''):
        print(row.rstrip())   # process here


def main():
    print("Nothing for now...")
    # init_sniffer()
    # tcp_dump()


if __name__ == "__main__":
    main()
