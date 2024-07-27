import socket
import threading
import time
import random
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import subrosa

BROADCAST_IP = '<broadcast>'
BUFFER_SIZE = 1024
BROADCAST_PORT = 12345

active = True
idd = random.randint(10, 50)
print(f"My id is {idd}")





def listen_for_broadcasts():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind(('', BROADCAST_PORT))
    while active:
        data, addr = udp_socket.recvfrom(BUFFER_SIZE)
        received_id, message = data.decode().split(':', 1)
        if int(received_id) != idd:
            print(f"Received from {received_id}: {message}")
    

def broadcast_message(message):
    udp_sending_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sending_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_sending_socket.sendto(message.encode(), (BROADCAST_IP, BROADCAST_PORT))
    udp_sending_socket.close()


def broadcast_periodically():
    i = 0
    while active:
        broadcast_message(f"{idd}:Hello from me {i}")
        time.sleep(10)
        i += 1


listener_thread = threading.Thread(target=listen_for_broadcasts)
listener_thread.daemon = True
listener_thread.start()

broadcaster_thread = threading.Thread(target=broadcast_periodically)
broadcaster_thread.daemon = True
broadcaster_thread.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Exiting...")