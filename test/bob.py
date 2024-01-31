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


ser_pk_dili, ser_sk_dili = gen_pk("Dili")
ser_pk_kyber, ser_sk_kyber = gen_pk("Kyber")
# r = gen_r()

message = b"This is the message to be sent"

# Connecting 
context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:5555")
print("Listerning ...")

# Exchange Public Key
client_pk_dili = socket.recv()
# print("Receiving {}".format(client_pk_dili))
socket.send(ser_pk_dili)
# print("Sending {}".format(client_pk_dili))
client_pk_kyber = socket.recv()
# print("Receiving {}".format(client_pk_kyber))
socket.send(ser_pk_kyber)
# print("Sending {}".format(client_pk_dili))


# Key Exchange
pk = msg_recv(socket, client_pk_dili)
# print("Receiving {}".format(pk))
msg_send(socket, b"RECEIVED", ser_sk_dili)
# print("Sending RECEIVED")
c2 = msg_recv(socket, client_pk_dili)
# print("Receiving {}".format(c2))
c, k = kyber_encaps(pk)
c1, k1 = kyber_encaps(client_pk_kyber)
_k2 = kyber_decaps(ser_sk_kyber, c2)

msg_send(socket, c, ser_sk_dili)
# print("Sending {}".format(client_pk_dili))
msg = msg_recv(socket, client_pk_dili)
# print("Receiving {}".format(msg))
msg_send(socket, c1, ser_sk_dili)
# print("Sending {}".format(client_pk_dili))
print("Key Exchange Complete.")

# Calculate the Shared Key

key = Kyber1024._h(k + k1 + _k2)
# _key = msg_recv(socket, client_pk_dili)
# print("Receiving {}".format(_key))


# Sending Message
shared_key = key[0:16]
msg = msg_recv(socket, client_pk_dili)
associateddata = msg[0:5]
nonce = msg[5: 5 + 16]
ciphertext = msg[5 + 16:]
r = ascon_decrypt(shared_key, nonce, associateddata, ciphertext, "Ascon-128")

msg_send(socket, r, ser_sk_dili)




# if key == _key:
#     print("same")
# else:
#     print("error")

# print(key)
# print(_key)


# c_pk_d = msg_recv(socket)
# time.sleep(1)
# msg_send(socket, pk_k)
# # c_pk_k = msg_recv(socket)
# # time.sleep(1)
# # socket.send(b"World")
# c = msg_recv(socket)
# time.sleep(1)
# socket.send(b"Received")
# sig = msg_recv(socket)
# time.sleep(1)
# socket.send(b"Received")

# ver = dili_verify(c, sig, c_pk_d)
# p = kyber_dec(c, sk_k)

# # print(p)
# if p == message:
#     print("same")
# else:
#     print("error")