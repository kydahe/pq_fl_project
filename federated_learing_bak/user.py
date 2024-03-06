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

server_info = {}

N = 50
NODE_NUM = 2

# User Client


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
    seed_msg = bytes("{}".format(random_number).encode('UTF-8'))
    variant="Ascon-Hash"
    hashlength = 32
    r = ascon_hash(seed_msg, variant, hashlength)
    return r

def gen_at(x_a, t, length=16):
    t_bytes = t.to_bytes(4, byteorder='big')
    a_t_bytes = ascon_mac(x_a[0:16], t_bytes, "Ascon-Prf", length)
    a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
    # print(a_t)
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
        if session_id in asnode_info:
            pk_d = asnode_info[session_id]['PK_SIGN']
        elif session_id in server_info:
            pk_d = server_info[session_id]['PK_SIGN']
        sig_bytes = base64.b64decode(sig)
        ver = dili_verify(str(msg).encode('utf-8'), sig_bytes, pk_d)
        return operation, session_id, content

def setup_phase(context, asnodes, node_aggs, server, server_agg, server_broad, user_id, client_pk_sign, client_sk_sign, client_pk_se, client_sk_se):
    socket = context.socket(zmq.REQ)
    i = 0
    
    # Round 1
    # Connecting to assisting nodes
    for i in range(0, len(asnodes)):
        # host, port = asnode
        node = asnodes[i]
        print("Connecting to Assisting Nodes {} ...".format(node))
        socket = context.socket(zmq.REQ)
        socket.connect(node)

        # Exchange Public Key with asnode
        pk_str = base64.b64encode(client_pk_sign).decode('utf-8')
        msg_send(socket, 'USER_KE_SIGN', user_id, pk_str)
        operation, asnode_id, content = msg_recv(socket)
        if asnode_id not in asnode_info:
            asnode_info[asnode_id] = {}
        asnode_info[asnode_id]['SETUP_ADDRESS'] = node
        asnode_info[asnode_id]['AGG_ADDRESS'] = node_aggs[i]
        if operation == 'NODE_KE_SIGN':
            pk_bytes = base64.b64decode(content)
            asnode_info[asnode_id]['PK_SIGN'] = pk_bytes
        
        pk_str = base64.b64encode(client_pk_se).decode('utf-8')
        msg_send(socket, 'USER_KE_SE', user_id, pk_str)
        operation, asnode_id, content = msg_recv(socket)
        if operation == 'NODE_KE_SE':
            pk_bytes = base64.b64decode(content)
            asnode_info[asnode_id]['PK_SE'] = pk_bytes
        
        print("Assiting Nodes Key Exchange Complete.")
        
        # print(asnode_info)

        # Secret Exchange
        msg_send(socket, 'SE_START', user_id, "SE_START", client_sk_sign, i)
        i = i+1
        operation, asnode_id, content = msg_recv(socket)
        if operation == 'SE_C':
            c_bytes = base64.b64decode(content)
            # print(content)
            shared_secret = kyber_decaps(client_sk_se, c_bytes)
            asnode_info[asnode_id]['SHARED_SECRET'] = shared_secret
            print(shared_secret)
        print("Shared Secret Exchange Complete.")
    
    # Connecting to Server
    print("Connecting to Server ...")
    socket = context.socket(zmq.REQ)
    socket.connect(server)

    # Exchange Public Key with server
    pk_str = base64.b64encode(client_pk_sign).decode('utf-8')
    msg_send(socket, 'USER_KE_SIGN', user_id, pk_str)
    operation, server_id, content = msg_recv(socket)
    if server_id not in server_info:
        server_info[server_id] = {}
    server_info[server_id]['SETUP_ADDRESS'] = server
    server_info[server_id]['AGG_ADDRESS'] = server_agg
    server_info[server_id]['BROAD_ADDRESS'] = server_broad
    # asnode_info[server_id]['SOCKET'] = socket
    if operation == 'KE_SIGN':
        pk_bytes = base64.b64decode(content)
        server_info[server_id]['PK_SIGN'] = pk_bytes
    
    print("Server Key Exchange Complete.")
    
    print("Setup Done.")
    
    # print(asnode_info)

def masking_updates(context, user_id, t, w, client_pk_sign, client_sk_sign):
    # server_id = -1
    i = 0
    a_t = np.zeros(len(w))
    for remote_id in asnode_info:
        if 'SHARED_SECRET' in asnode_info[remote_id]:
            x_a = asnode_info[remote_id]['SHARED_SECRET']
            x_a_prf = gen_at(x_a, t, len(w))
            a_t = a_t + x_a_prf
    
    # print(w)
    # print(w.dtype)
    # print(a_t.dtype)
    y_t = w + a_t
    
    y_t = y_t.astype(int)
    m = np.insert(y_t, 0, t)
    m_1 = np.array([t])
    # print(type(m))
    # print(type(m_1))
    
    for remote_id in asnode_info:
        # if 'SHARED_SECRET' in asnode_info[remote_id]:
        # socket = asnode_info[remote_id]['SOCKET']
        if 'PULL_SOCKET' in asnode_info[remote_id]:
            socket = asnode_info[remote_id]['PULL_SOCKET']
        else:
            socket = context.socket(zmq.PUSH)
            socket.connect(asnode_info[remote_id]['AGG_ADDRESS'])
            asnode_info[remote_id]['PULL_SOCKET'] = socket
        msg = np.array2string(m_1, separator=', ')
        msg_send(socket, 'USER_MASK_UPDATE', user_id, msg, client_sk_sign, i)
        i = i+1
        print("Sending Masking Update to Asnode {}: {}".format(remote_id, msg))
    
    for server_id in server_info:
        if 'PULL_SOCKET' in server_info[server_id]:
            socket = server_info[server_id]['PULL_SOCKET']
        else:
            socket = context.socket(zmq.PUSH)
            socket.connect(server_info[server_id]['AGG_ADDRESS'])
            server_info[server_id]['PULL_SOCKET'] = socket
        msg = np.array2string(m, separator=', ')
        msg_send(socket, 'USER_MASK_UPDATE', user_id, msg, client_sk_sign, i)
    
    print("Sending Masking Update to Server: {}".format(msg))
    print("Masking Update Done.")


def aggregation_updates(context):
    for server_id in server_info:
        if 'SUB_SOCKET' in server_info[server_id]:
            socket = server_info[server_id]['SUB_SOCKET']
        else:
            
            print("Connecting to Server ...")
            socket = context.socket(zmq.SUB)
            # print(server_info[server_id]['BROAD_ADDRESS'])
            socket.connect(server_info[server_id]['BROAD_ADDRESS'])
            socket.setsockopt(zmq.SUBSCRIBE, b'')
            server_info[server_id]['SUB_SOCKET'] = socket
        
        operation, remote_id, content = msg_recv(socket)
        if operation == 'SERVER_AGGR_BROAD':
            content_list = ast.literal_eval(content)
            w_f = np.array(content_list)
            # w_f = np.fromstring(content, dtype=int, sep=' ')
            print(w_f)
            print("Aggregation Complete.")
    print("Aggregation Update Done.")

def aggregation_phase(context, user_id, t, w, client_pk_sign, client_sk_sign):
    masking_updates(context, user_id, t, w, client_pk_sign, client_sk_sign)
    time.sleep(10)
    aggregation_updates(context)


def run_client(host, asnode_ports, server_ports, user_id):
    w_e = int(user_id)
    # print(w_e)
    w = np.array([w_e, w_e, w_e])
    t = 1
    client_pk_sign, client_sk_sign = gen_pk("Dili")
    client_pk_se, client_sk_se = gen_pk("Kyber")
    
    Dilithium2.precomputing(client_sk_sign, N*100)
    
    context = zmq.Context()
    
    node_setups = []
    node_aggs = []
    for i in range(0, NODE_NUM):
        node_setups.append("{}:{}".format(host, asnode_ports[i][0]))
        node_aggs.append("{}:{}".format(host, asnode_ports[i][1]))
    server_setup = "{}:{}".format(host, server_ports[0])
    server_agg = "{}:{}".format(host, server_ports[1])
    server_broad = "{}:{}".format(host, server_ports[2])
    
    
    """
    PQ-FL Setup phase
    """
    print("====================== Setup Phase ======================")
    setup_phase(context, node_setups, node_aggs, server_setup, server_agg, server_broad, user_id, client_pk_sign, client_sk_sign, client_pk_se, client_sk_se)
    print("=========================================================\n\n")
    
    """
    PQ-FL Aggregation phase
    """
    print("====================== Aggregation Phase ======================")
    aggregation_phase(context, user_id, t, w, client_pk_sign, client_sk_sign)




user_id = sys.argv[1]
host = "tcp://localhost"
asnode_ports = [[5600, 5601, 5602], [5610, 5611, 5612]]
# asnode_ports = [[5600, 5601, 5602]]
server_ports = [5500, 5501, 5502]
server = "tcp://localhost:5500"
run_client(host, asnode_ports, server_ports, user_id)