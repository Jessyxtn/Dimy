import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import subrosa
import socket
import threading
import random
import hashlib

BROADCAST_IP = '<broadcast>'
BUFFER_SIZE = 1024
BROADCAST_PORT = 12345

class DimyNode:
    def __init__(self):
        self.ephID_private = None
        self.ephID_public = None
        self.last_ephID_time = 0
        self.active = True
        self.sent_shares = []
        self.binary_shares = []
        self.shares_dict = {}

    def hash_ephid(self):
        return hashlib.sha256(self.ephid_tobytes()).digest()
    

    def generate_ephid(self):
        current_time = time.time()
        if current_time - self.last_ephID_time >= 15:
            self.ephID_private = X25519PrivateKey.generate()
            self.ephID_public = self.ephID_private.public_key()
            self.last_ephID_time = current_time
            print("----------------------------------- Generating new EphID -----------------------------------")
            print(f"Generated ephID: {self.ephid_tobytes().hex()}")

    def ephid_tobytes(self):
        ephID_bytes = self.ephID_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return ephID_bytes 
    
    def generate_shares(self):
        self.sent_shares.clear()
        key_bytes = self.ephid_tobytes()
        shares = subrosa.split_secret(key_bytes, 3, 5)
        self.binary_shares = [(i, bytes(share)) for i, share in enumerate(shares, 1)]
        print(f"Shares derived from EphID: {self.ephid_tobytes().hex()}")
        
        for index, share in self.binary_shares:
            print(f"    Share {index}: {share.hex()}")
        
        print(f"Hash: {self.hash_ephid().hex()}")
        print("--------------------------------------------------------------------------------------------")


    def reconstruct_shares(self, hash_id):
        shares_list = self.shares_dict[hash_id]
        
        received_shares = [subrosa.Share.from_bytes(share) for share in shares_list]
        reconstruct_ephid = subrosa.recover_secret(received_shares)
        print(f"Reconstructed Ephid: {reconstruct_ephid.hex()}")
        
        if hashlib.sha256(bytes(reconstruct_ephid)).digest() == hash_id:
            print(f"Hash of reconstructed ephid matches hash.")
            encid = self.compute_encid(reconstruct_ephid)
            print(f"Computed EncID: {encid.hex()}")
            self.store_encid_in_dbf(encid)
            
        return reconstruct_ephid
    
    def compute_encid(self, reconstructed_ephid):
        # converting the reconstructed ephid back into a public key object
        received_pub_key = X25519PublicKey.from_public_bytes(reconstructed_ephid)
        
        # using self's private key and other's public key to arrive at the shared key
        shared_key = self.ephID_private.exchange(received_pub_key)
        return shared_key
    
    def store_encid_in_dbf(self, encid):
        pass


    def listen_for_broadcasts(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind(('', BROADCAST_PORT))
        while self.active:
            data, _ = udp_socket.recvfrom(BUFFER_SIZE)
            hash_digest, share_n, share = data.split(b':', 2)
            if hash_digest != self.hash_ephid():
                print(f"Received share {int.from_bytes(share_n, byteorder='big')} from hash {hash_digest.hex()}")
                
            if hash_digest in self.shares_dict:
                self.shares_dict[hash_digest].append(share)
                self.check_shares(hash_digest)
            elif hash_digest != self.hash_ephid():
                self.shares_dict[hash_digest] = [share]
                

    def check_shares(self, hash_id):
        if len(self.shares_dict[hash_id]) == 3:
            self.reconstruct_shares(hash_id)

    def broadcast_message(self):
        # Condition 1: Message drop rate, if drop is less than 0.5 don't send message
        # Condition 2: If shares have not been generated yet, don't send message
        drop = random.random()
        if drop >= 0.5 and self.binary_shares:
            i, share = self.binary_shares.pop(0)
            message = self.hash_ephid() + b':' + i.to_bytes(1, byteorder='big') + b':' + share 
            print(f"Broadcasting share {i}")
            udp_sending_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sending_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            udp_sending_socket.sendto(message, (BROADCAST_IP, BROADCAST_PORT))
            udp_sending_socket.close()
            

    def broadcast_periodically(self):
        while self.active:
            self.broadcast_message()
            time.sleep(3)


    def run(self):
        listener_thread = threading.Thread(target=self.listen_for_broadcasts)
        listener_thread.daemon = True
        listener_thread.start()

        broadcaster_thread = threading.Thread(target=self.broadcast_periodically)
        broadcaster_thread.daemon = True
        broadcaster_thread.start()
        
        while True:
            self.generate_ephid()
            self.generate_shares()
            time.sleep(15)


node = DimyNode()
node.run()
