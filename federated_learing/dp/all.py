from opacus import PrivacyEngine
import torch
from torchvision import datasets, transforms
from torch.utils.data import DataLoader
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm
import numpy as np

import zmq
import json
import os
import sys
import math
from utils import *
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parent_dir = os.path.dirname(parent_dir)
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
import threading
from Crypto.Cipher import AES


from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS

init_uid = 1
init_nid = 5001

node_info = {}
N_SIGN = 40
NODE_NUM = 3
USER_NUM = int(sys.argv[1])
VEC_LEN = 16000  # 26010
sk_sign = b''
pk_sign = b''
sk_ex = b''
pk_ex = b''
# local_id = local_id
sign_count = 0
KE_DONE = False
iter_num = 0
user_ids = [str(init_uid + i) for i in range(USER_NUM)]
asnode_ids = [str(init_nid + i) for i in range(NODE_NUM)]
server_id = 10000


def generate_vector():
    w_arr = [bytes_to_int(gen_r()[:4]) for _ in range(VEC_LEN)]
    w = np.array(w_arr)
    for user_id in user_ids:
        # w_arr = [bytes_to_int(gen_r()[:4]) for _ in range(VEC_LEN)]
        # w = np.array(w_arr)
        # print("{} generate_vector".format(user_id))
        node_info[user_id]['VECTOR'][str(iter_num)] = w

def gen_at(x_a, t, length=16):
    # start_time = time.time()
    t_bytes = t.to_bytes(4, byteorder='big')
    
    # a_t_bytes = ascon_mac(x_a[0:16], t_bytes, "Ascon-Prf", length)
    # a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
    # print("bytes len {}".format(len(a_t_bytes)))
    # print(len(a_t))
    
    cipher = AES.new(x_a[0:16], AES.MODE_CTR, use_aesni='True')
    a_t_bytes = cipher.encrypt(t_bytes)*(math.ceil(VEC_LEN/4))
    a_t = np.frombuffer(a_t_bytes[0:VEC_LEN], dtype=np.uint8)
    # print("bytes len {}".format(len(a_t_bytes)))
    # print(cipher.nonce)
    
    # nonce_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    # chacha_algo = ChaCha20.new(key=x_a[0:32], nonce=nonce_bytes)
    # data = t_bytes
    # a_t_bytes = chacha_algo.encrypt(data) *4000
    # a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
    
    # print("gen_at time: {}".format(time.time()-start_time))
    return a_t


def msg_send_with_sig(operation, local_id, content, sig):
    msg = {'type': operation, 'session_id': local_id, 'content': content, 'sig': sig}
    return msg

def msg_recv_with_sig(resp):
    operation = resp.get('type')
    session_id = resp.get('session_id')
    content = resp.get('content')
    sig = resp.get('sig')
    return operation, session_id, content, sig

def msg_send_no_sig(operation, local_id, content):
    msg = {'type': operation, 'session_id': local_id, 'content': content}
    # socket.send_json(msg)
    return msg

def msg_recv_no_sig(resp):
    operation = resp.get('type')
    session_id = resp.get('session_id')
    content = resp.get('content')
    return operation, session_id, content

def msg_send(operation, local_id, content, base=10, signed=False):
    global sign_count
    if KE_DONE == False and signed == False:
        msg_to_sent = msg_send_no_sig(operation, local_id, content)
    else:
        # print("sig {}: {}".format(local_id, sign_count))
        sk_sign = node_info[local_id]['SK_SIGN']
        msg = {'type': operation, 'session_id': local_id, 'content': content}
        sig = dili_sign(str(msg).encode('utf-8'), sk_sign, sign_count)
        sig_str = base64.b64encode(sig).decode('utf-8')
        # print(sig_str)
        msg_to_sent = msg_send_with_sig(operation, local_id, content, sig_str)
        sign_count = (sign_count + 1) % base
    return msg_to_sent

def msg_recv(msg):
    # msg = socket.recv_json()
    if 'sig' not in msg:
        return msg_recv_no_sig(msg)
    else:
        operation, session_id, content, sig = msg_recv_with_sig(msg)
        msg = {'type': operation, 'session_id': session_id, 'content': content}
        # print("sig {}".format(session_id))
        # print(sig)
        pk_d = node_info[session_id]['PK_SIGN']
        sig_bytes = base64.b64decode(sig)
        ver = dili_verify(str(msg).encode('utf-8'), sig_bytes, pk_d)
        return operation, session_id, content

def setup_phase():
    node_info[server_id] = {}
    node_info[server_id]['MESSAGING'] = {}
    
    for node_id in user_ids:
        node_info[node_id] = {}
        node_info[node_id]['SHARED_SECRET'] = {}
        node_info[node_id]['VECTOR'] = {}
        node_info[node_id]['MESSAGING'] = {}
        node_info[node_id]['MASKINGS'] = {}
    
    for node_id in asnode_ids:
        node_info[node_id] = {}
        node_info[node_id]['SHARED_SECRET'] = {}
        node_info[node_id]['MESSAGING'] = {}
        node_info[node_id]['MASKINGS'] = {}
    
    for user_id in user_ids:
        for node_id in asnode_ids:
            # if 'MASKINGS' not in node_info[node_id]:
            #     node_info[node_id]['MASKINGS'] = {}
            node_info[node_id]['MASKINGS'][user_id] = {}
            # if 'MASKINGS' not in node_info[user_id]:
            #     node_info[user_id]['MASKINGS'] = {}
            node_info[user_id]['MASKINGS'][node_id] = {}
            # if 'MESSAGING' not in node_info[node_id]:
            #     node_info[node_id]['MESSAGING'] = {}
            # if 'MESSAGING' not in node_info[user_id]:
            #     node_info[user_id]['MESSAGING'] = {}
    
    pk_sign, sk_sign = gen_pk("Dili")
    pk_ex, sk_ex = gen_pk("Kyber")
    Dilithium2.precomputing(sk_sign, N_SIGN*15)
    node_info[server_id]['SK_SIGN'] = sk_sign
    node_info[server_id]['PK_SIGN'] = pk_sign
    print("{} generate key".format(server_id))
    
    for node_id in user_ids:
        pk_sign, sk_sign = gen_pk("Dili")
        pk_ex, sk_ex = gen_pk("Kyber")
        Dilithium2.precomputing(sk_sign, N_SIGN*15)
        node_info[node_id]['SK_SIGN'] = sk_sign
        node_info[node_id]['PK_SIGN'] = pk_sign
        if node_id in user_ids:
            node_info[node_id]['PK_EX'] = pk_ex
            node_info[node_id]['SK_EX'] = sk_ex
        print("{} generate key".format(node_id))
    
    for node_id in asnode_ids:
        pk_sign, sk_sign = gen_pk("Dili")
        pk_ex, sk_ex = gen_pk("Kyber")
        Dilithium2.precomputing(sk_sign, N_SIGN*15)
        node_info[node_id]['SK_SIGN'] = sk_sign
        node_info[node_id]['PK_SIGN'] = pk_sign
        print("{} generate key".format(node_id))
    
    for user_id in user_ids:
        c, k = kyber_encaps(node_info[user_id]['PK_EX'])
        # if 'SHARED_SECRET' not in node_info[user_id]:
        #     node_info[user_id]['SHARED_SECRET'] = {}
        for node_id in asnode_ids:
            # if 'SHARED_SECRET' not in node_info[node_id]:
            #     node_info[node_id]['SHARED_SECRET'] = {}
            node_info[node_id]['SHARED_SECRET'][user_id] = k
            node_info[user_id]['SHARED_SECRET'][node_id] = k
        
        # print("{} generate shared secret".format(user_id))



# masking_precomputing for one client
def masking_precomputing_oc(user_id):
    for node_id in asnode_ids:
        x_a = node_info[user_id]['SHARED_SECRET'][node_id]
        x_a_prf = gen_at(x_a, iter_num, VEC_LEN)
        node_info[node_id]['MASKINGS'][user_id][str(iter_num)] = x_a_prf
        node_info[user_id]['MASKINGS'][node_id][str(iter_num)] = x_a_prf

        
def client_masking_updates(user_id, precomputing):
    
    # Client
    a_t = np.zeros(VEC_LEN)
    if precomputing:
        for node_id in asnode_ids:
            a_t = a_t + node_info[user_id]['MASKINGS'][node_id][str(iter_num)]
    else:
        for node_id in asnode_ids:
            x_a = node_info[user_id]['SHARED_SECRET'][node_id]
            x_a_prf = gen_at(x_a, iter_num, len(w))
            a_t = a_t + x_a_prf
    
    w = node_info[user_id]['VECTOR'][str(iter_num)]
    a_t = a_t.astype(int)
    y_t = w + a_t
    
    y_t = y_t.astype(int)
    m = np.insert(y_t, 0, iter_num)
    m_1 = np.array([iter_num])
    
    # end_time = time.time()
    # print("{} masking_updates vector: {}".format(user_id, end_time - start_time))
    
    # start_time_1 = time.time()
    msg_vec = np.array2string(m_1, separator=', ', threshold=np.inf)
    msg_asnode = msg_send('USER_MASK_UPDATE', user_id, msg_vec)
    
    msg_vec = np.array2string(m, separator=', ', threshold=np.inf)
    msg_server = msg_send('USER_MASK_UPDATE', user_id, msg_vec)
    
    # end_time = time.time()
    # print("{} masking_updates message signing: {}".format(user_id, (end_time - start_time_1)))
    # print("{} masking_updates message construction: {}".format(user_id, (end_time - start_time)*1000))
    
    
    for node_id in asnode_ids:
        node_info[node_id]['MESSAGING'][user_id] = msg_asnode
    node_info[server_id]['MESSAGING'][user_id] = msg_server
        


def client_aggregation_updates(user_id):
    # start_time = time.time()
    update_vec = np.zeros(VEC_LEN)
    msg = node_info[user_id]['MESSAGING'][server_id]
    operation, remote_id, content = msg_recv(msg)
    content_list = ast.literal_eval(content)
    update_vec = np.array(content_list)
    # print(update_vec)
    
    

# def client_aggregation_phase(user_id, precomputing=False):
#     masking_updates(user_id, precomputing)
#     # time.sleep(10)
#     aggregation_updates(user_id)

def server_masking_updates():
    user_updates = []
    node_updates = []
    
    for user_id in user_ids:
        user_msg = node_info[server_id]['MESSAGING'][user_id]
        operation, remote_id, content = msg_recv(user_msg)
        content_list = ast.literal_eval(content)
        w_t = np.array(content_list)
        if iter_num != int(w_t[0]):
            print("Iteration Numer from User {} is not correct: receive {} but should be {}.".format(remote_id, w_t[0], iter_num))
        user_updates.append(w_t[1:])
    
    for node_id in asnode_ids:
        node_msg = node_info[server_id]['MESSAGING'][node_id]
        operation, remote_id, content = msg_recv(node_msg)
        content_list = ast.literal_eval(content)
        a_t = np.array(content_list)
        if iter_num != int(a_t[0]):
            print("Iteration Numer from Node {} is not correct: receive {} but should be {}.".format(remote_id, a_t[0], iter_num))
        node_updates.append(a_t[2:])
    
    return user_updates, node_updates


def calc_final_w(user_updates, node_updates):
    # sum up user vectors
    u_stacks = np.stack(user_updates)
    u_sum = np.sum(u_stacks, axis=0)
    
    # sum up asnode vectors
    n_stacks = np.stack(node_updates)
    n_sum = np.sum(n_stacks, axis=0)
    
    final_w = u_sum - n_sum
    return final_w

def server_aggregation_updates(user_updates, node_updates):
    w = calc_final_w(user_updates, node_updates)
    
    msg_vec = np.array2string(w, separator=', ', threshold=np.inf)
    msg = msg_send('SERVER_AGGR_BROAD', server_id, msg_vec)
    # print(w)
    for user_id in user_ids:
        node_info[user_id]['MESSAGING'][server_id] = msg
    
def aggregation_phase():
    user_updates, node_updates = server_masking_updates()
    server_aggregation_updates(user_updates, node_updates)

def node_masking_updates(node_id):
    u_c = 0
    for user_id in user_ids:
        msg = node_info[node_id]['MESSAGING'][user_id]
        operation, remote_id, content = msg_recv(msg)
        content_list = ast.literal_eval(content)
        if iter_num != int(np.array(content_list)[0]):
            print("Iteration Numer from User {} is not correct: receive {} but should be {}.".format(user_id, int(np.array(content_list)[0]), iter_num))
            continue
        u_c = u_c + 1
    return u_c


def node_aggregation_updates(node_id, user_count, precomputing):
    
    a_t = np.zeros(VEC_LEN)
    if precomputing:
        for user_id in user_ids:
            a_t = a_t + node_info[node_id]['MASKINGS'][user_id][str(iter_num)]
    else:
        for user_id in user_ids:
            x_a = node_info[node_id]['SHARED_SECRET'][user_id]
            x_a_prf = gen_at(x_a, iter_num, VEC_LEN)
            a_t = a_t + x_a_prf
    
    
    a_t = a_t.astype(int)
    m = a_t
    m = np.insert(m, 0, iter_num)
    m = np.insert(m, 1, user_count)
    
    msg_vec = np.array2string(m, separator=', ', threshold=np.inf)
    msg_server = msg_send('USER_MASK_UPDATE', node_id, msg_vec)
    
    node_info[server_id]['MESSAGING'][node_id] = msg_server

def node_aggregation_phase(node_id, precomputing=False):
    user_count = masking_updates(node_id)
    aggregation_updates(node_id, user_count, precomputing)


print("User number = {}, Assisting Node number = {}".format(USER_NUM, NODE_NUM))
print("====================== Setup Phase ======================")
start_time = time.time()
setup_phase()
KE_DONE = True
end_time = time.time()
print("Total setup_phase time = {}".format((end_time - start_time)*1000))

print("++++++++++++ generate_vector ++++++++++++")
start_time = time.time()
generate_vector()
end_time = time.time()
print("Total generate_vector time = {}".format((end_time - start_time)*1000))


print("++++++++++++ masking_precomputing ++++++++++++")
used_time = []
for user_id in user_ids:
    start_time = time.time()
    masking_precomputing_oc(user_id)
    end_time = time.time()
    used_time.append((end_time - start_time)*1000)

client_pre = np.mean(np.array(used_time))
print("One user masking_precomputing time = {}".format(np.mean(np.array(used_time))))


print("====================== Aggregation Phase ======================")
print("++++++++++++ client_masking_updates ++++++++++++")
used_time = []
for user_id in user_ids:
    start_time = time.time()
    client_masking_updates(user_id, precomputing=True)
    end_time = time.time()
    used_time.append((end_time - start_time)*1000)

client_mu = np.mean(np.array(used_time))
print("One user client_masking_updates time = {}".format(np.mean(np.array(used_time))))

print("++++++++++++ node_aggregation ++++++++++++")
used_time = []
used_time1 = []
for node_id in asnode_ids:
    start_time = time.time()
    user_count = node_masking_updates(node_id)
    used_time1.append((time.time() - start_time)*1000)
    node_aggregation_updates(node_id, user_count, precomputing=True)
    end_time = time.time()
    used_time.append((end_time - start_time)*1000)

node_agg = np.mean(np.array(used_time))
print("One assisting node node_masking_updates time = {}".format(np.mean(np.array(used_time1))))
print("One assisting node node_aggregation time = {}".format(np.mean(np.array(used_time))))

print("++++++++++++ server_aggregation ++++++++++++")
# print("++++++++++++ server_masking_updates ++++++++++++")
# start_time = time.time()
user_updates, node_updates = server_masking_updates()


# print("++++++++++++ server_aggregation_updates ++++++++++++")
start_time = time.time()
server_aggregation_updates(user_updates, node_updates)
end_time = time.time()
server_agg = (end_time - start_time)*1000
print("Server server_aggregation time = {}".format((end_time - start_time)*1000))

print("++++++++++++ client_aggregation_updates ++++++++++++")
used_time = []
for user_id in user_ids:
    start_time = time.time()
    client_aggregation_updates(user_id)
    end_time = time.time()
    used_time.append((end_time - start_time)*1000)

client_agg = np.mean(np.array(used_time))
print("One client client_aggregation_updates time = {}".format(np.mean(np.array(used_time))))

iter_num = iter_num + 1

print("====================== Done ======================")
print("Total Time without precomputation: {}".format(client_mu + node_agg + server_agg + client_agg))
print("+ precomputation: {}".format(client_pre + client_mu + node_agg + server_agg + client_agg))