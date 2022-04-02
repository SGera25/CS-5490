from ctypes.wintypes import BYTE
import random as rand
import pyDes as DES
import hashlib
import keys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
from Crypto.PublicKey import RSA

'''
Library of networking and cryptography helper functions
ported from Programming Project 1, updated with some new 
and revised functions. Uses Crypto.RSA for certificates, 
and PyDes for 3DES encryption.

Sam Gera (u1173758) 
4/1/22
CS 5490 PP2
'''

# Port for client and server to communicate on
CS_PORT = 3158

# Encoding for strings
ENCODING = 'UTF-8'

# Byteorder
BYTEORDER = 'little'

# Stream size for file streaming
STREAMSIZE = 2000

# Modes for record header
HANDSHAKE = 0 # During Handshake phase
DATA = 23 # During Data streaming
FINISHED = 24 # At end of streaming

# Keys
client_keys = RSA.import_key(keys.key1)
server_keys = RSA.import_key(keys.key2)

# Generate Bytes (padded) for a 64-bit ulong
def get_ulong():

    # Generate random 64-bit long (padded to 8 bytes)
    return rand.getrandbits(64).to_bytes(8, 'little')


# Initiate contact given a socket object
def initiate(m, s, PORT):
    try:
        # Init connection
        s.connect(('localhost', PORT))

        # Send initiation message
        s.send(m)
        print("Sent initiation message")
    except:
        print("Error while sending initiation message")
        s.close()
        quit()

# Wait for initiation , and returns the corresponding socket
def get_connection(s):
    try:
        # Wait for connection on AB_PORT
        print("Waiting for connection")
        s.listen(1)
        conn, addr = s.accept()
        print("Connection Recieved")

        # Decode initiation message 
        m = conn.recv(256)
        print("Message recieved from connection")
        return conn, m
    except:
        print("Error while recieving initiation message")
        s.close()
        quit()

# Create a certificate by signing the public key with your private key (self-signing)
def sign(pk, prk):
    # Create signature object using private key
    signer = pkcs1_15.new(prk)

    # Create a MD of the public key
    MD = SHA384.new(pk.export_key('PEM'))
    certificate = signer.sign(MD)
    return certificate

# Verify certificate given Certificate and public key
def verify(c, pk):
    print("Verifying certificate with Public key:")

    # Create a MD of the public key to verify signature
    MD = SHA384.new(pk.export_key('PEM'))

    # Create a verifier
    verifier = pkcs1_15.new(pk)
    try:
        verifier.verify(MD, c)
    except:
        print("Certificate was not authentic..")
        print("Exiting...")
        quit()
    print("Signed public key matched known public key after decryption")
    print("Certificate Trusted!")

# Add Record header (assuming m is already encoded)
def record_header(m, mode):
    header = mode.to_bytes(1, BYTEORDER)
    # Version
    header += (768).to_bytes(2,BYTEORDER)
    # Length of message in bytes
    header += (len(m)).to_bytes(2, BYTEORDER)
    header += m
    return header

# Given a message containing a recorder header, decode it's elements and return the plaintext m
def decode_header(m):
    print("Found message with:")
    try:
        mode = m[0]
        print("Mode: %d (%s)" % (mode, mode_to_string(mode)))
        version = m[1:3]
        print("Version: %s" % hex(int.from_bytes(version, BYTEORDER)))
        length = m[3:5]
        print("Length: %d" % int.from_bytes(length, BYTEORDER))
        plain = m[5:5 + int.from_bytes(length, BYTEORDER)]
        print("Message: %s\n" % plain)
        return mode, version, length, plain
    except:
        print("Error while decoding header off recieved message.\nExiting...")
        quit()

# Create an internal file header given file bytes and an HMAC
def encode_fheader(data, hmac):
    m = len(data).to_bytes(2, BYTEORDER)
    m += data + hmac
    return m

# Decode the internal file header
def decode_fheader(m):
    # Read the 2-byte header that denotes the size of the file
    file_size = int.from_bytes(m[0:2], BYTEORDER)
    print("\nRecieved %d bytes of the file\n" % file_size)

    # Retrieve the file and HMAC
    data = m[2:file_size+2]
    integrity = m[file_size+2:]
    return data, integrity

def mode_to_string(mode):
    if(mode == 0):
        return "Handshake"
    elif(mode == 23):
        return "Data"
    return "Finished"

# Send message m as plaintext
def send_m(m, s):
    try:
        s.send(m)
        print("Sent message:\n%s" % m)
    except:
        print("Error sending message")
        quit()
    return

# Recv plain text 
def recv_m(s):
    try:
        m = s.recv(8192)
        print("Message recieved:")
        print(m)
        return m
    except:
        print("Error while recieving message")
        quit()

# Do 3DES(ECB) Encryption on a message
def encrypt_ecb(m, key):
    c = DES.triple_des(key, DES.ECB)
    return c.encrypt(m)

# Do 3DES(CBC) Encryption on a message
def encrypt_cbc(m, key, IV):
    c = DES.triple_des(key, DES.CBC, IV)
    return c.encrypt(m)

# Do 3DES(ECB) decryption on a message
def decrypt_ecb(m, key):
    c = DES.triple_des(key, DES.ECB)
    return c.decrypt(m)

# DO 3DES(CBC) decryption on a message
def decrypt_cbc(m, key, IV):
    c = DES.triple_des(key, DES.CBC, IV)
    return c.decrypt(m)

# Format the message to be a multiple of 8 bytes and return the byte array
def form_m(m):
    pad = (8-(len(m) % 8)) * b'\0'
    m = m + pad
    return m

# Better output
def output(s, id):
    print("\n" + id + " " + str(s))

# Encrypt using the public key
def encrypt_RSA(m, pk):
    cipher = PKCS1_OAEP.new(pk)
    return cipher.encrypt(m)

# Decrypt using private key
def decrypt_RSA(m, prk):
    cipher = PKCS1_OAEP.new(prk)
    return cipher.decrypt(m)

# given the two nonces make the secret key 
def make_secret(R1, R2):
    R1 = int.from_bytes(R1, BYTEORDER)
    R2 = int.from_bytes(R2, BYTEORDER)
    return (R1 ^ R2).to_bytes(8, BYTEORDER)

# Given a master secret, naively generate a set of 4 keys
def generate_keys(secret):
    k1 = secret[:2] + ((b'\0') * 14)
    k2 = secret[:4] + ((b'\0') * 12)
    k3 = secret[:6] + ((b'\0') * 10)
    k4 = secret + ((b'\0') * 8)
    return k1, k2, k3, k4

# Generate SHA1(k | SHA1(m | k)) for integrity/authentication protection
def HMAC(m, key):
    h = hashlib.sha1(m + key)
    h2 = hashlib.sha1(key + h.digest())
    return h2.digest()
