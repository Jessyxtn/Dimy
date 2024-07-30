import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import subrosa
import socket
import threading
import random
import hashlib
import select
from BloomFilter import BloomFilter
import sys

BROADCAST_IP = '<broadcast>'
BUFFER_SIZE = 1024
BROADCAST_PORT = 12345
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 55111

class DimyNode:
    def __init__(self):
        self.ephID_private = None
        self.ephID_public = None
        self.last_ephID_time = 0
        self.active = True
        self.sent_shares = []
        self.binary_shares = []
        self.shares_dict = {}
        
        self.dbf_lock = threading.Lock()
        self.dbf_list = []
        self.current_dbf = None
        self.current_dbf_start_time = None
        self.no_covid = True
        

    def hash_ephid(self):
        return hashlib.sha256(self.ephid_tobytes()).digest()

    def generate_ephid(self):
        current_time = time.time()
        if current_time - self.last_ephID_time >= 15:
            self.ephID_private = X25519PrivateKey.generate()
            self.ephID_public = self.ephID_private.public_key()
            self.last_ephID_time = current_time
            print("----------------------------------------- Segment 1 -----------------------------------------")
            print(f"Generated ephID: {self.ephid_tobytes().hex()}")
            print("---------------------------------------------------------------------------------------------")


    def ephid_tobytes(self):
        ephID_bytes = self.ephID_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return ephID_bytes 
    
    def check_shares(self, hash_id):
        if len(self.shares_dict[hash_id]) == 3:
            self.reconstruct_shares(hash_id)

    def generate_shares(self):
        self.sent_shares.clear()
        key_bytes = self.ephid_tobytes()
        shares = subrosa.split_secret(key_bytes, 3, 5)
        self.binary_shares = [(i, bytes(share)) for i, share in enumerate(shares, 1)]
        print("\n----------------------------------------- Segment 2 -----------------------------------------")
        print(f"Shares derived from EphID: {self.ephid_tobytes().hex()}")

        for index, share in self.binary_shares:
            print(f"    Share {index}: {share.hex()}")
        
        print(f"Hash: {self.hash_ephid().hex()}")
        print("---------------------------------------------------------------------------------------------\n")


    def reconstruct_shares(self, hash_id):
        reconstruct_ephid = None
        shares_list = self.shares_dict[hash_id]
        try:
            received_shares = [subrosa.Share.from_bytes(share) for share in shares_list]
            reconstruct_ephid = subrosa.recover_secret(received_shares)
            print("---------------------------------------- Segment 4-A ----------------------------------------")
            print(f"Reconstructed Ephid: {reconstruct_ephid.hex()[6]}")
            print("---------------------------------------------------------------------------------------------\n")

            if hashlib.sha256(bytes(reconstruct_ephid)).digest() == hash_id:
                print("---------------------------------------- Segment 4-B ----------------------------------------")
                print(f"Hash of reconstructed ephid matches advertised hash.")
                print("---------------------------------------------------------------------------------------------\n")

                encid = self.compute_encid(reconstruct_ephid)
                print("--------------------------------------- Segment 5-A/B ---------------------------------------")
                print(f"Computed EncID: {encid.hex()}")
                print("---------------------------------------------------------------------------------------------\n")
                self.process_new_encid(encid)
        except NotImplementedError as e:
            pass
            
        return reconstruct_ephid
    
    def compute_encid(self, reconstructed_ephid):
        # converting the reconstructed ephid back into a public key object
        received_pub_key = X25519PublicKey.from_public_bytes(reconstructed_ephid)
        # using self's private key and other's public key to arrive at the shared key
        shared_key = self.ephID_private.exchange(received_pub_key)
        return shared_key
    

    def process_new_encid(self, encid):
        with self.dbf_lock:
            # check that a dbf exists
            if not self.current_dbf:
                self.current_dbf = BloomFilter()
                self.current_dbf_start_time = time.time()
            
            current_time = time.time()
            if current_time - self.current_dbf_start_time > 90:
                print("---------------------------------------- Segment 7-B ----------------------------------------")
                print("Creating a new DBF after 90 seconds")
                # adding the old dbf too a list
                self.dbf_list.append(self.current_dbf)
                # creating the new dbf
                self.current_dbf = BloomFilter()
                self.current_dbf_start_time = current_time
                print(f"Current number of stored DBFs: {len(self.dbf_list)}")

                print("--------------------------------------------------------------------------------------------\n")


        print("----------------------------------------- Segment 6 -----------------------------------------")
        self.current_dbf.add(encid)
        print("# Encounter has been encoded into DBF")
        # check the dbfs after processing new encid
        self.check_dbfs()
        print("---------------------------------------- Segment 7-A ----------------------------------------")
        print(f"# DBF state after encoding EncID: {self.current_dbf.get_n_bits_set()} bits have been set.")
        del encid
        print("# EncID has been deleted.")
        print("--------------------------------------------------------------------------------------------\n")


    def check_dbfs(self, current_time=time.time()):
        if self.dbf_list:
            with self.dbf_lock:
                # check that the number of dbfs is not greater than 6
                while len(self.dbf_list) > 6:
                    self.dbf_list.pop(0)
                
                # remove dbfs that are older than 9 mins
                ttl = 9 * 60  # 9 mins
                # create a tmp copy of the dbf list to loop through
                tmp_dbf_list = self.dbf_list.copy()
                for dbf in tmp_dbf_list:
                    # If it has been more than 9 mins since the creation of the dbf
                    # remove it from the original list
                    if current_time - dbf.get_time() > ttl:
                        self.dbf_list.remove(dbf)
            
    def combine_dbfs(self):
        print("Combining all DBFs into one.")
        combined_dbfs = BloomFilter()
        with self.dbf_lock:
            for dbf in self.dbf_list:
                combined_dbfs.bit_array |= dbf.bit_array
            if self.current_dbf:
                combined_dbfs.bit_array |= self.current_dbf.bit_array
        return combined_dbfs
    
    def handle_qbf(self):
        while self.no_covid:
            time.sleep(9 * 60) # wait for 9 mins
            if not self.no_covid:
                break
            
            # Checking the dbfs are all up to date before adding it to a qbf
            print("-------------------------------------------- Segment 8 --------------------------------------")
            self.check_dbfs(time.time())
            qbf = self.combine_dbfs()
            print(f"# Number of bits set in QBF: {qbf.get_n_bits_set()}")
            print("---------------------------------------------------------------------------------------------\n")
            # send qbf to the backend server
            self.send_qbf(qbf)
            
    def send_qbf(self, qbf):
        print("------------------------------------------- Segment 10-A/B ------------------------------------")
        print("# Sending QBF to backend server")
        command = "qbf:"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((SERVER_HOST, SERVER_PORT))
                message = command.encode() + qbf.get_bit_array_bytes()
                s.sendall(message)
                # Receive the response
                response = s.recv(1024).decode()
                print(f"Server response: ")
                

        except Exception as e:
            print(f"{e}:Send qbf: Error sendin QBF to server")
        print("---------------------------------------------------------------------------------------------\n")


    def listen_for_broadcasts(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind(('', BROADCAST_PORT))
        while self.active:
            data, _ = udp_socket.recvfrom(BUFFER_SIZE)
            hash_digest, share_n, share = data.split(b':', 2)
            if hash_digest != self.hash_ephid():
                print("--------------------------------------- Segment 3-B/C ---------------------------------------")
                print(f"# Received share {int.from_bytes(share_n, byteorder='big')} from hash {hash_digest.hex()}")
                print("---------------------------------------------------------------------------------------------\n")

            if hash_digest in self.shares_dict:
                self.shares_dict[hash_digest].append(share)
                self.check_shares(hash_digest)
            elif hash_digest != self.hash_ephid():
                self.shares_dict[hash_digest] = [share]
            

    def broadcast_message(self):
        # Condition 1: Message drop rate, if drop is less than 0.5 don't send message
        # Condition 2: If shares have not been generated yet, don't send message
        if self.binary_shares:
            drop = random.random()
            print("---------------------------------------- Segment 3-A ----------------------------------------")
            print("Preparing to broadcast share.")
            if drop >= 0.5:
                i, share = self.binary_shares.pop(0)
                message = self.hash_ephid() + b':' + i.to_bytes(1, byteorder='big') + b':' + share 
                print(f"Broadcasting share {i}")
                udp_sending_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sending_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                udp_sending_socket.sendto(message, (BROADCAST_IP, BROADCAST_PORT))
                udp_sending_socket.close()
            else:
                print("Share dropped.")
            print("---------------------------------------------------------------------------------------------\n")
            

    def broadcast_periodically(self):
        while self.active:
            self.broadcast_message()
            time.sleep(3)


    def user_input_handler(self):
        # code adapted from here:
        # https://stackoverflow.com/questions/1335507/keyboard-input-with-timeout
        while self.active and self.no_covid:
            print("Enter 'p' to report COVID-19 positive (upload CBF):\n")
            
            # use select to implement a timeout for user input
            read, _, _ = select.select([sys.stdin], [], [], 8)
            if read:
                # remove all the trailing spaces incl. newline
                user_input = sys.stdin.readline().strip()
                if user_input.lower() == "p":
                    print(f"User reported covid positive.")
                    
                    # upload the cbf
                    self.no_covid = False
                    self.upload_cbf()
                    break

    def upload_cbf(self):
        self.check_dbfs(time.time())
        print("----------------------------------------- Segment 9 -----------------------------------------")
        cbf = self.combine_dbfs()
        command = "cbf:"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((SERVER_HOST, SERVER_PORT))
                message = command.encode() + cbf.get_bit_array_bytes()
                s.sendall(message)
    
                response = s.recv(1024).decode()
                if response:
                    print("CBF successfully uploaded to the server.")
        except Exception as e:
            print(f"{e}:Send qbf: Error sendin CBF to server")
        print("---------------------------------------------------------------------------------------------\n")


    def run(self):
        listener_thread = threading.Thread(target=self.listen_for_broadcasts)
        listener_thread.daemon = True
        listener_thread.start()

        broadcaster_thread = threading.Thread(target=self.broadcast_periodically)
        broadcaster_thread.daemon = True
        broadcaster_thread.start()
        
        query_thread = threading.Thread(target=self.handle_qbf)
        query_thread.daemon = True
        query_thread.start()
        
        report_thread = threading.Thread(target=self.user_input_handler)
        report_thread.daemon = True
        report_thread.start()

        while True:
            self.generate_ephid()
            self.generate_shares()
            time.sleep(15)

if __name__ == "__main__":
    node = DimyNode()
    node.run()
