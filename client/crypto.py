# crypto_utils.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# ✅ AES-256 requires a 32-byte (256-bit) key
AES_KEY = b'ThisIsA32ByteLongSecretKeyForAES'


def encrypt_file(input_path, output_path):
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        fout.write(iv)
        while chunk := fin.read(4096):
            fout.write(encryptor.update(chunk))
        fout.write(encryptor.finalize())

def decrypt_file(input_path, output_path):
    backend = default_backend()
    with open(input_path, 'rb') as fin:
        iv = fin.read(16)
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=backend)
        decryptor = cipher.decryptor()
        with open(output_path, 'wb') as fout:
            while chunk := fin.read(4096):
                fout.write(decryptor.update(chunk))
            fout.write(decryptor.finalize())
