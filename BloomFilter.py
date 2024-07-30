import bitarray
import mmh3
import time

# Code taken and adapted from here: https://www.geeksforgeeks.org/bloom-filters-introduction-and-python-implementation/

class BloomFilter(object):
    def __init__(self):
        # 100KB bits
        self.size = 100 * 1024 * 8
        self.num_hashes = 3
        self.bit_array = bitarray.bitarray(self.size)
        self.bit_array.setall(0)
        self.creation_time = time.time()
    
    def hash_item(self, encid, seed):
        return mmh3.hash(encid, seed) % self.size
    
    def add(self, encid):
        """ Add encid to the Bloom filters """
        for i in range(self.num_hashes):
            hashed_i = self.hash_item(encid, seed=i)
            self.bit_array[hashed_i] = 1
    
    def get_time(self):
        return self.creation_time
    
    def get_n_bits_set(self):
        return sum(self.bit_array)
    
    def get_bit_array_bytes(self):
        return self.bit_array.tobytes()
    
    @classmethod
    def from_bytes(cls, byte_data):
        bf = cls()
        bf.bit_array = bitarray.bitarray()
        bf.bit_array.frombytes(byte_data)
        return bf

    def match(self, other_bf):
        result = self.bit_array & other_bf.bit_array
        matched_bits = result.count(1)
        print(f"Matched bits: {matched_bits}")
        # Return true if there are 3 or more matched bits
        # Else return false
        return matched_bits >= 3