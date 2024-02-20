import zmq
import json
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
import base64
import numpy as np
import ast

user_info = {}
server_info = {}
N = 50
USER_NUM = 2
W_LEN = 3


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


def gen_at(x_a, t, length=16):
    t_bytes = t.to_bytes(4, byteorder='big')
    a_t_bytes = ascon_mac(x_a[0:16], t_bytes, "Ascon-Prf", length)
    a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
    return a_t


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

def dili_sign(msg, sk, i=0):
    sig, _, __ = Dilithium2.sign_precomputed_only(sk, msg, N, N*i)
    return sig

def dili_verify(msg, sig, pk):
    ver = Dilithium2.verify_precomputed(pk, msg, sig)
    print("verify result = {}".format(ver)) 
    return ver

def kyber_encaps(pk):
    c, key = Kyber1024.enc(pk)
    return c, key

def kyber_decaps(sk, c):
    key = Kyber1024.dec(c, sk)
    return key


def msg_pack_send(socket, operation, session_id, content, sig):
    msg = {'type': operation, 'session_id': session_id, 'content': content, 'sig': sig}
    socket.send_json(msg)
    
def msg_pack_recv(resp):
    operation = resp.get('type')
    session_id = resp.get('session_id')
    content = resp.get('content')
    sig = resp.get('sig')
    return operation, session_id, content, sig



def msg_send_ke(socket, operation, session_id, content):
    msg = {'type': operation, 'session_id': session_id, 'content': content}
    # print(msg)
    socket.send_json(msg)

def msg_recv_ke(resp):
    operation = resp.get('type')
    session_id = resp.get('session_id')
    content = resp.get('content')
    return operation, session_id, content

def msg_send(socket, operation, session_id, content, sk_d="", i=0):
    if sk_d == "":
        msg_send_ke(socket, operation, session_id, content)
    else:
        msg = {'type': operation, 'session_id': session_id, 'content': content}
        sig = dili_sign(str(msg).encode('utf-8'), sk_d, i)
        sig_str = base64.b64encode(sig).decode('utf-8')
        msg_pack_send(socket, operation, session_id, content, sig_str)


def msg_recv(socket):
    msg = socket.recv_json()
    if 'sig' not in msg:
        return msg_recv_ke(msg)
    else:
        operation, session_id, content, sig = msg_pack_recv(msg)
        msg = {'type': operation, 'session_id': session_id, 'content': content}
        pk_d = user_info[session_id]['PK_SIGN']
        sig_bytes = base64.b64decode(sig)
        ver = dili_verify(str(msg).encode('utf-8'), sig_bytes, pk_d)
        return operation, session_id, content


def setup_phase(context, host, port, asnode_id, server_host, server_port, asnode_pk_sign, asnode_sk_sign, asnode_pk_se, asnode_sk_se):
    socket = context.socket(zmq.REQ)
    server = "{}:{}".format(server_host, server_port)
    socket.connect(server)
    server_info['SETUP_ADDRESS'] = server
    pk_str = base64.b64encode(asnode_pk_sign).decode('utf-8')
    msg_send(socket, 'NODE_KE_SIGN', asnode_id, pk_str)
    # operation, server_id, content = msg_recv(socket)
    # server_info['ID'] = server_id
    # if operation == 'KE_SIGN':
    #     pk_bytes = base64.b64decode(content)
    #     server_info['PK_SIGN'] = pk_bytes
    
    print("Server Key Exchange Complete.")
    
    
    socket = context.socket(zmq.REP)
    socket.bind("{}:{}".format(host, port))
    print("Listerning ...")
    u_c = 0
    while True:
        operation, user_id, content = msg_recv(socket)
        if user_id not in user_info:
            user_info[user_id] = {}
        if operation == 'USER_KE_SIGN':
            user_info[user_id]['PK_SIGN'] = base64.b64decode(content)
            pk_str = base64.b64encode(asnode_pk_sign).decode('utf-8')
            msg_send(socket, 'NODE_KE_SIGN', asnode_id, pk_str)
            print("Receive PK_SIGN from User {}.".format(user_id))
        elif operation == 'USER_KE_SE':
            user_info[user_id]['PK_SE'] = base64.b64decode(content)
            pk_str = base64.b64encode(asnode_pk_se).decode('utf-8')
            msg_send(socket, 'NODE_KE_SE', asnode_id, pk_str)
            print("Receive PK_SE from User {}.".format(user_id))
            # print(user_info)
        elif operation == 'SE_START':
            # print(user_info[user_id]['PK_SE'])
            c, k = kyber_encaps(user_info[user_id]['PK_SE'])
            user_info[user_id]['SHARED_SECRET'] = k
            c_str = base64.b64encode(c).decode('utf-8')
            # print(c_str)
            msg_send(socket, 'SE_C', asnode_id, c_str, asnode_sk_sign, u_c)
            u_c = u_c + 1
            print("Sending SE_C to User {}.".format(user_id))
            # print(k)
        if u_c == USER_NUM:
            break
    
    print("User Key/Shared Secret Exchange Complete.")
    print("Setup Done.")

def masking_updates(context, host, port, asnode_pk_sign, asnode_sk_sign):
    socket = context.socket(zmq.PULL)
    socket.bind("{}:{}".format(host, port))
    print("Listerning ...")
    u_c = 0
    t = -1
    while True:
        operation, user_id, content = msg_recv(socket)
        if user_id not in user_info:
            print("ERROR")
        if operation == 'USER_MASK_UPDATE':
            # print(content)
            # print(type(content))
            # print(np.fromstring(content, dtype=int, sep=' '))
            content_list = ast.literal_eval(content)
            user_info[user_id]['T'] = np.array(content_list)[0] # np.fromstring(content, dtype=int, sep=' ')[0]
            t = user_info[user_id]['T']
            u_c = u_c + 1
            print("Receive USER_MASK_UPDATE from User {}.".format(user_id))
        if u_c == USER_NUM:
            break
    
    print("Masking Update Done.")
    # print(t)
    # print(type(t))
    return int(t)
    

def aggregation_updates(context, asnode_id, server_host, server_port, t, asnode_pk_sign, asnode_sk_sign):
    # t = user_info[0]['T']
    for user_id in user_info:
        if t != user_info[user_id]['T']:
            print("T is not same!")
    
    a_t = np.zeros(W_LEN)
    for remote_id in user_info:
        if 'SHARED_SECRET' in user_info[remote_id]:
            x_a = user_info[remote_id]['SHARED_SECRET']
            x_a_prf = gen_at(x_a, t, W_LEN)
            a_t = a_t + x_a_prf
    
    a_t = a_t.astype(int)
    m = a_t
    m = np.insert(m, 0, t)
    m = np.insert(m, 1, USER_NUM)
    if 'PULL_SOCKET' in server_info:
        socket = server_info['PULL_SOCKET']
    else:
        socket = context.socket(zmq.PUSH)
        server_info['AGG_ADDRESS'] = "{}:{}".format(server_host, server_port)
        socket.connect(server_info['AGG_ADDRESS'])
        server_info['PULL_SOCKET'] = socket
    msg = np.array2string(m, separator=', ')
    msg_send(socket, 'NODE_MASK_UPDATE', asnode_id, msg, asnode_sk_sign, 0)
    print("Sending Masking Update to Server: {}".format(msg))
    print("Aggregation Update Done.")

def aggregation_phase(context, host, port, asnode_id, server_host, server_port, asnode_pk_sign, asnode_sk_sign):
    t = masking_updates(context, host, port, asnode_pk_sign, asnode_sk_sign)
    aggregation_updates(context, asnode_id, server_host, server_port, t, asnode_pk_sign, asnode_sk_sign)



def run_asnode(host, ports, server_host, server_ports, asnode_id):
    asnode_pk_sign, asnode_sk_sign = gen_pk("Dili")
    asnode_pk_se, asnode_sk_se = gen_pk("Kyber")
    
    Dilithium2.precomputing(asnode_sk_sign, N*100)
    
    context = zmq.Context()
    
    """
    PQ-FL Setup Phase
    """
    print("====================== Setup Phase ======================")
    setup_phase(context, host, ports[0], asnode_id, server_host, server_ports[0], asnode_pk_sign, asnode_sk_sign, asnode_pk_se, asnode_sk_se)
    print("=========================================================\n\n")
    
    """
    PQ-FL Aggregation Phase
    """
    print("====================== Aggregation Phase ======================")
    aggregation_phase(context, host, ports[1], asnode_id, server_host, server_ports[1], asnode_pk_sign, asnode_sk_sign)
    
    

    
    


aid = sys.argv[1]
init_port = sys.argv[2]
host = "tcp://*"
ports = []
ports.append(int(init_port))
ports.append(int(init_port)+1)
ports.append(int(init_port)+2)
# ports = [5600, 5601, 5602]
server_host = "tcp://localhost"
server_ports = [5500, 5501]
run_asnode(host, ports, server_host, server_ports, aid)