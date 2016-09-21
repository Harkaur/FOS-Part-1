import struct

from Crypto.Cipher import XOR

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # This can be broken into code run just on the server or just on the client
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
            self.shared_hash = shared_hash
            # References

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

