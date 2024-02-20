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

asnode_info = {}
user_info = {}
N = 50
USER_NUM = 2
ASNODE_NUM = 2


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
        if session_id in asnode_info:
            pk_d = asnode_info[session_id]['PK_SIGN']
        elif session_id in user_info:
            pk_d = user_info[session_id]['PK_SIGN']
        sig_bytes = base64.b64decode(sig)
        ver = dili_verify(str(msg).encode('utf-8'), sig_bytes, pk_d)
        return operation, session_id, content

def setup_phase(context, host, port, server_id, server_pk_sign, server_sk_sign):
    socket = context.socket(zmq.REP)
    socket.bind("{}:{}".format(host, port))
    print("Listerning ...")
    while True:
        operation, remote_id, content = msg_recv(socket)
        if operation == 'USER_KE_SIGN':
            if remote_id not in user_info:
                user_info[remote_id] = {}
            user_info[remote_id]['PK_SIGN'] = base64.b64decode(content)
            print("Receive PK_SIGN from User {}.".format(remote_id))
        elif operation == 'NODE_KE_SIGN':
            if remote_id not in asnode_info:
                asnode_info[remote_id] = {}
            asnode_info[remote_id]['PK_SIGN'] = base64.b64decode(content)
            print("Receive PK_SIGN from Assisting Node {}.".format(remote_id))
        pk_str = base64.b64encode(server_pk_sign).decode('utf-8')
        msg_send(socket, 'KE_SIGN', server_id, pk_str)
        if len(user_info) == USER_NUM and len(asnode_info) == ASNODE_NUM:
            break
    print("Setup Done.")


def masking_updates(context, host, port, server_pk_sign, server_sk_sign):
    user_updates = []
    node_updates = []
    socket = context.socket(zmq.PULL)
    socket.bind("{}:{}".format(host, port))
    start_time = time.time()
    u_c = 0
    n_c = 0
    while True:
        end_time = time.time()
        if end_time - start_time > 300:
            print("Masking Update Timeout.")
            break
        operation, remote_id, content = msg_recv(socket)
        if operation == 'USER_MASK_UPDATE':
            # print(content)
            content_list = ast.literal_eval(content)
            w_t = np.array(content_list)
            # w_t = np.fromstring(content, dtype=int, sep=' ')
            user_info[remote_id]['MASK_UPDATE'] = w_t
            user_updates.append(w_t)
            u_c = u_c + 1
            print("Receive USER_MASK_UPDATE from User {}: {}".format(remote_id, w_t))
        elif operation == 'NODE_MASK_UPDATE':
            content_list = ast.literal_eval(content)
            a_t = np.array(content_list)
            # a_t = np.fromstring(content, dtype=int, sep=' ')
            asnode_info[remote_id]['MASK_UPDATE'] = a_t
            node_updates.append(a_t)
            n_c = n_c + 1
            print("Receive NODE_MASK_UPDATE from Assisting Node {}: {}".format(remote_id, a_t))
        if u_c == USER_NUM and n_c == ASNODE_NUM:
            break
    print("Masking Update Done.")
    return user_updates, node_updates


def calc_final_w(user_updates, node_updates):
    # check t
    t = user_updates[0][0]
    u_updates = []
    for user_update in user_updates:
        if t != user_update[0]:
            print("(User) Not Same t")
        u_updates.append(user_update[1:])
    
    user_count = len(user_updates)
    n_updates = []
    for node_update in node_updates:
        if t != node_update[0]:
            print("(Node) Not Same t")
        if user_count != node_update[1]:
            print("(Node) Not Same user_count")
            # print(user_count)
            # print(node_update[1])
        n_updates.append(node_update[2:])
    
    # sum up user vectors
    u_stacks = np.stack(u_updates)
    u_sum = np.sum(u_stacks, axis=0)
    
    # sum up asnode vectors
    n_stacks = np.stack(n_updates)
    n_sum = np.sum(n_stacks, axis=0)
    
    final_w = u_sum - n_sum
    return final_w
    

def aggregation_updates(context, host, port, server_id, server_pk_sign, server_sk_sign, user_updates, node_updates):
    w = calc_final_w(user_updates, node_updates)
    
    socket = context.socket(zmq.PUB)
    # print("{}:{}".format(host, port))
    socket.bind("{}:{}".format(host, port))
    time.sleep(10)
    msg = np.array2string(w, separator=', ')
    msg_send(socket, 'SERVER_AGGR_BROAD', server_id, msg, server_sk_sign, 0)
    print(w)
    print("Aggregation Update Done.")
    
    

def aggregation_phase(context, host, ports, server_id, server_pk_sign, server_sk_sign):
    user_updates, node_updates = masking_updates(context, host, ports[0], server_pk_sign, server_sk_sign)
    aggregation_updates(context, host, ports[1], server_id, server_pk_sign, server_sk_sign, user_updates, node_updates)

def run_server(host, ports, server_id):
    server_pk_sign, server_sk_sign = gen_pk("Dili")
    server_pk_se, server_sk_se = gen_pk("Kyber")
    
    Dilithium2.precomputing(server_sk_sign, N*100)
    
    context = zmq.Context()
    
    """
    PQ-FL Setup Phase
    """
    print("====================== Setup Phase ======================")
    setup_phase(context, host, ports[0], server_id, server_pk_sign, server_sk_sign)
    print("=========================================================\n\n")
    
    """
    PQ-FL Aggregation Phase
    """
    print("====================== Aggregation Phase ======================")
    aggregation_phase(context, host, ports[1:], server_id, server_pk_sign, server_sk_sign)
    
    
    
    


    


host = "tcp://*"
ports = [5500, 5501, 5502, 5503]
sid = 1000
run_server(host, ports, sid)