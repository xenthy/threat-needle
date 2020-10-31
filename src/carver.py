import os
import re
import string
import random
from io import BytesIO
from vault import Vault
from config import SESSION_CACHE_PATH, CARVED_DIR
from features import extract_payload
from logger import logging, LOG_FILE, FORMATTER, TIMESTAMP

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(FORMATTER, TIMESTAMP)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


class Carver:
    """
    Specifying the different types of magic bytes for different filetypes (in decimals)
    """
    file_sigs = {"jgp": ['255', '216'], "jpeg": ['255', '216'], "png": ['137', '80'], "gif": ['71', '73'], "pdf": ['37', '80', '68', '70'], "docx": ['80', '75', '3', '4']}

    @staticmethod
    def carve_stream(k, timestamp, cont_type, cont_length, stream_payload):
        """
        Main carving function to carve out files from packet streams' payloads
        """
        magic = ""
        k = k.replace(" ", "_").replace(":", "-")

        bytes_content = BytesIO(stream_payload)
        for file_type, magic_bytes in Carver.file_sigs.items():
            if file_type == cont_type:
                magic = magic_bytes
                break

        if cont_type and cont_length and magic:
            sof = Carver.get_sof(magic, bytes_content)
            if sof is None:
                return 0

            eof = sof + cont_length
            view = bytes_content.getbuffer()
            carved = view[sof:eof]

            with open(f"{CARVED_DIR}{(fname := Carver.random_str(5))}.{cont_type}", 'ab+') as file_obj:
                file_obj.write(carved)
                logger.info(f"File {fname}.{cont_type} carved ({cont_length} bytes)")
                Vault.add_carved_file(k, timestamp, f"{fname}.{cont_type}", cont_length)

            return carved

    @staticmethod
    def get_content_info(payload_b):
        """
        Retrieve the stream payload's content type and its content lenght
        - To be stored and used in carve_stream()
        """
        cont_type = ""
        cont_length = 0

        view = payload_b.getvalue()
        lines = (str(view)).split("\\n")

        for line in lines:
            if not cont_length:
                cont_length = re.findall(r"Content\_Length:\ (\w+)", line)
            if not cont_type:
                cont_type = re.findall(r"Content\_Type:\ \w+/(\w+)", line)

            if cont_type and cont_length:
                return cont_type[0], int(cont_length[0])

        return None, None

    @staticmethod
    def get_sof(magic, payload_b):
        """
        Find the Start of File bytes based on the content-length specified in the packet/streams and the filetype's magic bytes
        """
        num_bytes = len(magic)
        byte_count = 0
        payload_b.seek(0)
        all_bytes = payload_b.read()

        for i in range(0, len(all_bytes)-(num_bytes-1)):
            compare = ""
            for j in range(0, num_bytes):
                compare += str(all_bytes[i+j])

            if ''.join(magic) in compare:
                return byte_count

            byte_count += 1

        return None

    @staticmethod
    def random_str(length):
        """
        Used to set random strings as the carved filenames
        """
        letters = string.ascii_lowercase
        result = ''.join(random.choice(letters) for i in range(length))
        return result
