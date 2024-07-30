import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import subrosa
import socket
import threading
import random
import hashlib
from BloomFilter import BloomFilter

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 55111

def send_qbf(qbf):
    command = "qbf:"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            message = command.encode() + qbf.get_bit_array_bytes()
            print(message)
            s.sendall(message)
            # Receive the response
            # response = s.recv(1024).decode()
            return None #response
    except Exception as e:
        print(f"{e}:Send qbf: Error sendin QBF to server")
        
        
if __name__ == "__main__":
    qbf = BloomFilter()
    send_qbf(qbf)