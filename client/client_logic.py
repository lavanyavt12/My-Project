import socket
import ssl
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 4443
BUFFER_SIZE = 4096

AES_KEY = b'ThisIsA32ByteLongSecretKeyForAES'
AES_IV = b'ThisIsAnInitVect'                     # 16 bytes

def encrypt_file(filename):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(filename, 'rb') as f:
        data = f.read()

    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    enc_filename = f"{filename}.enc"
    with open(enc_filename, 'wb') as f:
        f.write(encrypted)

    return enc_filename

def send_msg(ssl_sock, msg):
    ssl_sock.sendall((msg + '\n').encode())

def recv_msg(ssl_sock):
    data = b""
    while not data.endswith(b'\n'):
        chunk = ssl_sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode().strip()

def login_user(username, password):
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations('server.crt')

        raw_sock = socket.create_connection((SERVER_HOST, SERVER_PORT))
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=SERVER_HOST)

        send_msg(ssl_sock, f"LOGIN {username} {password}")
        response = recv_msg(ssl_sock)

        if response == "LOGIN_SUCCESS":
            print("[+] Login successful.")
            return ssl_sock
        else:
            print("[-] Login failed.")
            ssl_sock.close()
            return None
    except Exception as e:
        print(f"[!] Login error: {e}")
        return None

def upload_file(username, password, filepath):
    ssl_sock = login_user(username, password)
    if not ssl_sock:
        return False

    if not os.path.exists(filepath):
        print("[-] File does not exist.")
        ssl_sock.close()
        return False

    try:
        enc_filename = encrypt_file(filepath)
    except Exception as e:
        print(f"[!] Upload error: {e}")
        ssl_sock.close()
        return False

    try:
        send_msg(ssl_sock, "UPLOAD")
        send_msg(ssl_sock, os.path.basename(filepath))

        with open(enc_filename, 'rb') as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                ssl_sock.sendall(chunk)

        ssl_sock.sendall(b"EOF")

        response = recv_msg(ssl_sock)
        if response == "UPLOAD_SUCCESS":
            print("[+] File uploaded successfully.")
            ssl_sock.close()
            os.remove(enc_filename)
            return True
        else:
            print("[-] Upload failed.")
            ssl_sock.close()
            return False
    except Exception as e:
        print(f"[!] Upload error: {e}")
        ssl_sock.close()
        return False

def register_user(username, password):
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations('server.crt')

        raw_sock = socket.create_connection((SERVER_HOST, SERVER_PORT))
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=SERVER_HOST)

        send_msg(ssl_sock, f"REGISTER {username} {password}")
        response = recv_msg(ssl_sock)
        ssl_sock.close()

        return response == "REGISTER_SUCCESS"
    except Exception as e:
        print(f"[!] Register error: {e}")
        return False
