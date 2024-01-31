import zmq
import os
import sys
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)
sys.path.insert(0, parent_dir+"/dilithium_py")
original_cwd = os.getcwd()
os.chdir(parent_dir+"/dilithium_py")
from dilithium_py.dilithium import *
sys.path.insert(0, parent_dir+"/pyascon")
original_cwd = os.getcwd()
os.chdir(parent_dir+"/pyascon")
from ascon import *
sys.path.insert(0, parent_dir+"/kyber_py")
original_cwd = os.getcwd()
os.chdir(parent_dir+"/kyber_py")
from kyber_py.kyber import *
import time
import random

# Client


def int_to_bytes(num):
    return num.to_bytes(4, byteorder='big', signed=False)


def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big', signed=False)


def gen_dili_pk():
    pk, sk = Dilithium2.keygen()
    # print(len(sk))
    return pk, sk

def gen_kyber_pk():
    # pk, sk = Kyber1024._cpapke_keygen()
    pk, sk = Kyber1024.keygen()
    # print(len(sk))
    return pk, sk

def gen_pk(opt="Dili"):
    if opt == "Dili":
        return gen_dili_pk()
    else:
        return gen_kyber_pk()


def gen_r():
    random_number = random.randint(0, 4294967295)
    # seed_msg = bytes("Message is {}".format(random_number).encode('UTF-8'))
    seed_msg = bytes("{}".format(random_number).encode('UTF-8'))
    variant="Ascon-Hash"
    hashlength = 32
    r = ascon_hash(seed_msg, variant, hashlength)
    # print(random_number)
    # print(r.hex())
    return r

def padding(msg, target_len):
    msg_len = len(msg)
    padding_len = (target_len - msg_len)
    padding = []
    padding.extend([padding_len for _ in range(padding_len)])
    return msg + bytes(padding)

def unpadding(msg):
    msg_len = len(msg)
    padding_len = int(msg[-1])
    return msg[0:msg_len - padding_len]

def kyber_enc(plaintext, pk, r):
    target_len = int(Kyber1024.n / 8)
    msg_padding = padding(plaintext, target_len)
    ciphertext = Kyber1024._cpapke_enc(pk, msg_padding, r)
    return ciphertext

def kyber_dec(ciphertext, sk):
    msg = Kyber1024._cpapke_dec(sk, ciphertext)
    # print(msg)
    plaintext = unpadding(msg)
    return plaintext

def dili_sign(msg, sk):
    sig, _, __ = Dilithium2.sign(sk, msg, precomputed=True)
    return sig

def dili_verify(msg, sig, pk):
    ver = Dilithium2.verify(pk, msg, sig)
    print("verify result = {}".format(ver)) 
    return ver

def kyber_encaps(pk):
    c, key = Kyber1024.enc(pk)
    return c, key

def kyber_decaps(sk, c):
    key = Kyber1024.dec(c, sk)
    return key

def msg_pack_send(socket, c, sig):
    msg_len = len(c)
    bytes_len = int_to_bytes(msg_len)
    packet = bytes_len + c + sig
    socket.send(packet)
    
def msg_pack_recv(socket):
    msg = socket.recv()
    msg_len = bytes_to_int(msg[0:4])
    c = msg[4: 4 + msg_len]
    sig = msg[4 + msg_len : ]
    return c, sig



def msg_send(socket, msg, sk_d):
    sig = dili_sign(msg, sk_d)
    msg_pack_send(socket, msg, sig)


def msg_recv(socket, pk_d):
    msg, sig = msg_pack_recv(socket)
    ver = dili_verify(msg, sig, pk_d)
    return msg


client_pk_dili, client_sk_dili = gen_pk("Dili")
client_pk_kyber, client_sk_kyber = gen_pk("Kyber")
r = gen_r()


message = b"This is the message to be sent"

# Connecting
context = zmq.Context()
print("Connecting to Bob (server) ...")
socket = context.socket(zmq.REQ)
socket.connect("tcp://localhost:5555")


# Exchange Public Key
socket.send(client_pk_dili)
# print("Sending {}".format(client_pk_dili))
ser_pk_dili = socket.recv()
# print("Receiving {}".format(ser_pk_dili))
socket.send(client_pk_kyber)
# print("Sending {}".format(client_pk_kyber))
ser_pk_kyber = socket.recv()
# print("Receiving {}".format(ser_pk_kyber))


# Key Exchange
pk, sk = gen_pk("Kyber")
c2, k2 = kyber_encaps(ser_pk_kyber)
msg_send(socket, pk, client_sk_dili)
# print("Sending {}".format(pk))
msg = msg_recv(socket, ser_pk_dili)
# print("Receiving {}".format(msg))
msg_send(socket, c2, client_sk_dili)
# print("Sending {}".format(c2))

c = msg_recv(socket, ser_pk_dili)
# print("Receiving {}".format(c))
msg_send(socket, b"RECEIVED", client_sk_dili)
# print("Sending RECEIVED")
c1 = msg_recv(socket, ser_pk_dili)
# print("Receiving {}".format(c1))
_k = kyber_decaps(sk, c)
_k1 = kyber_decaps(client_sk_kyber, c1)
print("Key Exchange Complete.")


# Calculate the Shared Key
key = Kyber1024._h(_k + _k1 + k2)
# msg_send(socket, key, client_sk_dili)
# print("Sending {}".format(key))
# print(len(key)) # 32 bytes


# Sending Message
nonce1   = get_random_bytes(16)
nonce = get_random_bytes(16) 
r = ascon_mac(nonce1, nonce, "Ascon-Prf", taglength=32)
associateddata = b"ASCON"

shared_key = key[0:16]
nonce = get_random_bytes(16) 
ciphertext = ascon_encrypt(shared_key, nonce, associateddata, r,  "Ascon-128")


msg_send(socket, associateddata + nonce + ciphertext, client_sk_dili)

_r = msg_recv(socket, ser_pk_dili)

if r == _r:
    print("same")
else:
    print("error")

# c = kyber_enc(message, s_pk_k, r)
# sig = dili_sign(c, sk_d)

# msg_send(socket, c)
# msg = msg_recv(socket)
# print(msg)
# msg_send(socket, sig)
# msg = msg_recv(socket)
# print(msg)


# context = zmq.Context()

# #  Socket to talk to server
# print("Connecting to Bob (server) ...")
# socket = context.socket(zmq.REQ)
# socket.connect("tcp://localhost:5555")

# #  Do 10 requests, waiting each time for a response
# for request in range(10):
#     print("Sending request %s …" % request)
#     socket.send(b"Hello")

#     #  Get the reply.
#     message = socket.recv()
#     print("Received reply %s [ %s ]" % (request, message))


# c = kyber_enc(message, pk_k, r)
# sig = dili_sign(c, sk_d)

# ver = dili_verify(c, sig, pk_d)
# p = kyber_dec(c, sk_k)

# # print(p)
# if p == message:
#     print("same")
# else:
#     print("error")
