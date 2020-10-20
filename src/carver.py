import re
import os
import io
import glob
import yara
import string
import random
from io import BytesIO
from vault import Vault
from config import SESSION_CACHE_PATH, CARVED_DIR


class Carver:
    def __init__(self):
        file_sigs = {"jgp":['255', '216'], "jpeg":['255','216'], "png":['137', '80'], "gif":['71', '73'], "pdf":['37', '80', '68', '70'], "docx":['80', '75', '3', '4']}


    def carve_stream(self, stream_payload):
        magic = ""
        # cont_type, cont_length = self.get_content_info(b)
        carving_queue= Vault.get_carving_queue()

        for k, timestamp, cont_type, cont_length in carving_queue:
            with open(f"{SESSION_CACHE_PATH}/{k}",'rb') as f:
                stream_payload = f.read()
                
            b = BytesIO(stream_payload)
            for ft, mb in self.file_sigs.items():
                if ft == cont_type:
                    magic = mb
                    break
            
            if cont_type and cont_length and magic:
                SOF = self.get_SOF(magic, b)
                if not SOF:
                    return 0
                
                EOF = SOF + cont_length

                view = b.getbuffer()
                carved = view[SOF:EOF]

                with open(f"{SESSION_CACHE_PATH}/{Vault.get_runtime_name()}/{(fname := self.random_str)}."+cont_type,'ab+') as f:
                    f.write(carved)
                    Vault.add_carved_file(k, timestamp, f"{fname}.{cont_type}", cont_length)


                
                return carved

    # def carve_packet(self, packet):
        # pass

    def get_content_info(self, payload_b):
        cont_type  = ""
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
        

    def get_SOF(self, magic, payload_b):
        num_bytes = len(magic)
        byte_count = 0
        payload_b.seek(0)
        all_bytes = payload_b.read()

        for i in range(0, len(all_bytes)-(num_bytes-1)):
            compare = ""
            for x in range(0,num_bytes):
                compare += str(all_bytes[i+x])

            print(''.join(magic),compare)
            if ''.join(magic) in compare:
                return byte_count

            byte_count += 1
    
        return 0
    
    def random_str(self, length):
        letters = string.ascii_lowercase
        result = ''.join(random.choice(letters) for i in range(length))
        return result


if __name__ == "__main__":
    carver = Carver()
    stream = ""
    with open("../carved/yakgm.txt", 'rb') as f:
        stream = f.read()
        
    carver.carve_stream(stream)
