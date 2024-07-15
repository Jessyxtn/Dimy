import sys
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import binascii

class DimyNode:
    def __init__(self):
        self.ephid_private = None
        self.ephid = None
        self.last_ephid_time = 0

    def generate_ephid(self):
        current_time = time.time()
        if current_time - self.last_ephid_time >= 15:
            self.ephid_private = X25519PrivateKey.generate()
            self.ephid = self.ephid_private.public_key()
            self.last_ephid_time = current_time

    
    def publickey_tohex(self):
        raw_public_bytes = self.ephid.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        public_key_hex = binascii.hexlify(raw_public_bytes).decode('utf-8')

        return public_key_hex        
    
    def run(self):
        while True:
            time.sleep(1)




node = DimyNode()
node.run()
