import sys
import socket
import threading
from BloomFilter import BloomFilter
import time

BLOOM_FILTER_SIZE = 100 * 1024 
COMMAND = 4

class DimyServer():
    def __init__(self, host, port) -> None:
        self.host = host
        self.port = port
        self.server_socket = None
        self.cbf_list = []
        self.cbf_timestamps = []
        self.active = True
        
    
    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server is listening on {self.host}:{self.port}")
        
        while True:
            self.server_socket.listen()
            client_socket, client_addr = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_addr))
            client_thread.start()
    
    def handle_client(self, client_socket, client_addr):
        print(f"New connection from {client_addr}.")
        # code taken from: https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
        while self.active:
            try:
                data = self.recv_all(client_socket, COMMAND + BLOOM_FILTER_SIZE)
            
                if data:
                    command, bf_data = data.split(b':', 1)
                    command = command.decode()
                    print(f"Received command: {command}")
                    if command == 'qbf':
                        qbf = BloomFilter.from_bytes(bf_data)
                        print(f"Number of bits set in QBF: {qbf.get_n_bits_set()}")
                        # perform a matching with all the cbf
                        # send results back to the client
                        if self.match_qbf(qbf):
                            result = "match"
                        else:
                            result = "no match"
                        client_socket.sendall(result.encode())
                        
                    elif command == 'cbf':
                        cbf = BloomFilter.from_bytes(bf_data)
                        self.add_cbf(cbf)
                        print(f"Number of bits set in CBF: {cbf.get_n_bits_set()}")
                        client_socket.sendall(b"CBF received and stored.")
                
            except Exception as e:
                print(f"An error occurred: {e}")
        client_socket.close()
        
        print(f"Connection from {client_addr} closed.")
    
    def recv_all(self, sock, size):
        data = bytearray()
        while len(data) < size:
            packet = sock.recv(size - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data
    
    def match_qbf(self, qbf):
        print("---------------------------------------- Segment 10-C ---------------------------------------")
        print("Performing QBF-CBF matching:")
        for cbf in self.cbf_list:
            if qbf.match(cbf):
                print("A match has been found.")
                return True
        print("No matches found in any CBFs.")
        print("---------------------------------------------------------------------------------------------\n")
        return False

    
    def add_cbf(self, cbf):
        """Add a new CBF to the cbf database

        Args:
            cbf (BloomFilter): bloom filters
        """
        current_time = time.time()
        self.cbf_list.append(cbf)
        self.cbf_timestamps.append(current_time)
        

if __name__ == "__main__":
    server = DimyServer('127.0.0.1', 55111)
    print("Dimy Backend Server Starting...")
    server.start()