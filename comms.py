import struct
import base64

from Crypto.Cipher import XOR
from Crypto.Hash import SHA256

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.key = None
        self.iv = None
        self.shared_hash = None
        self.initiate_session()

    def initiate_session(self):
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            self.send(bytes(str(my_public_key), "ascii"))
            # Send them our public key
            their_public_key = int(self.recv())
            # Receive their public key
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            # Obtain our shared secret
            print("Shared hash: {}".format(shared_hash))
            # Prints shared hash on session establishment
            self.key = self.shared_hash[32:]
            # Took this key from the last 32 bytes of shared key
            self.shared_hash = shared_hash
            #Shared key is referenced
            self.iv = self.shared_hash[16:]
            # IV is from the last 16 bytes of shared key
            print("SELF.IV in INITIATE_SESSION is: " + str(self.iv))
            # Prints IV as a string
            print(SELF.KEY is: " + str(self.key))
            #prints self as string
            self.cipher = (self.key, AES.MODE_CBC, self.iv)
            
            

        # Default XOR algorithm can only take a key of length 32
        self.cipher = XOR.new(shared_hash[:4])

    def send(self, data):
        if self.cipher:
            encrypted_data = self.cipher.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            data = self.cipher.decrypt(encrypted_data)
            if self.verbose:
                print("Receiving packet of lenimport struct

