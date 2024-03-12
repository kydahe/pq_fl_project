import zmq
import json
import os
import sys
from utils import *
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
import threading
from Crypto.Cipher import AES


from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS

# user_info = {}
# server_info = {}
# N = 50
# USER_NUM = 2
# W_LEN = 3

class AssistingNode:
    def __init__(self, asnode_id, host, port_setup, port_update):
        self.user_info = {}
        self.server_info = {}
        self.N_SIGN = 50
        self.USER_NUM = 10
        self.VEC_LEN = 16000
        self.sk_sign = b''
        self.pk_sign = b''
        self.sk_ex = b''
        self.pk_ex = b''
        self.asnode_id = asnode_id
        self.host = host
        self.port_setup = port_setup
        self.port_update = port_update
        self.socket_setup = None
        self.socket_update = None
        self.sign_count = 0
        self.KE_DONE = False
        self.iter_num = 0
    
    def gen_at(self, x_a, t, length=16):
        # start_time = time.time()
        t_bytes = t.to_bytes(4, byteorder='big')
        
        # a_t_bytes = ascon_mac(x_a[0:16], t_bytes, "Ascon-Prf", length)
        # a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
        
        cipher = AES.new(x_a[0:16], AES.MODE_CTR, use_aesni='True')
        a_t_bytes = cipher.encrypt(t_bytes)*4000
        a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
        # print(cipher.nonce)
        
        
        # nonce_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        # chacha_algo = ChaCha20.new(key=x_a[0:32], nonce=nonce_bytes)
        # data = t_bytes
        # a_t_bytes = chacha_algo.encrypt(data) *4000
        # a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
        
        # print("gen_at time: {}".format(time.time()-start_time))
        return a_t

    def msg_send_with_sig(self, socket, operation, content, sig):
        msg = {'type': operation, 'session_id': self.asnode_id, 'content': content, 'sig': sig}
        socket.send_json(msg)

    def msg_recv_with_sig(self, resp):
        operation = resp.get('type')
        session_id = resp.get('session_id')
        content = resp.get('content')
        sig = resp.get('sig')
        return operation, session_id, content, sig

    def msg_send_no_sig(self, socket, operation, content):
        msg = {'type': operation, 'session_id': self.asnode_id, 'content': content}
        socket.send_json(msg)

    def msg_recv_no_sig(self, resp):
        operation = resp.get('type')
        session_id = resp.get('session_id')
        content = resp.get('content')
        return operation, session_id, content

    def msg_send(self, socket, operation, content, signed=False):
        if self.KE_DONE == False and signed == False:
            self.msg_send_no_sig(socket, operation, content)
        else:
            # print("sig")
            msg = {'type': operation, 'session_id': self.asnode_id, 'content': content}
            sig = dili_sign(str(msg).encode('utf-8'), self.sk_sign, self.sign_count)
            sig_str = base64.b64encode(sig).decode('utf-8')
            self.msg_send_with_sig(socket, operation, content, sig_str)
            self.sign_count = (self.sign_count + 1) % 50

    def msg_recv(self, socket):
        msg = socket.recv_json()
        if 'sig' not in msg:
            return self.msg_recv_no_sig(msg)
        else:
            # print("sig")
            operation, session_id, content, sig = self.msg_recv_with_sig(msg)
            msg = {'type': operation, 'session_id': session_id, 'content': content}
            pk_d = self.user_info[session_id]['PK_SIGN']
            sig_bytes = base64.b64decode(sig)
            ver = dili_verify(str(msg).encode('utf-8'), sig_bytes, pk_d)
            return operation, session_id, content

    def setup_phase(self, context, server_host, server_port, socket_setup):
        socket = context.socket(zmq.REQ)
        server = "{}:{}".format(server_host, server_port)
        socket.connect(server)
        self.server_info['SETUP_ADDRESS'] = server
        pk_str = base64.b64encode(self.pk_sign).decode('utf-8')
        self.msg_send(socket, 'NODE_KE_SIGN', pk_str)
        
        # print("Server Key Exchange Complete.")
        
        
        self.socket_setup = socket_setup
        u_c = 0
        while True:
            operation, user_id, content = self.msg_recv(socket_setup)
            if user_id not in self.user_info:
                self.user_info[user_id] = {}
            if operation == 'USER_KE_SIGN':
                self.user_info[user_id]['PK_SIGN'] = base64.b64decode(content)
                pk_str = base64.b64encode(self.pk_sign).decode('utf-8')
                self.msg_send(socket_setup, 'NODE_KE_SIGN', pk_str)
                # print("Receive PK_SIGN from User {}.".format(user_id))
            elif operation == 'USER_KE_SE':
                self.user_info[user_id]['PK_SE'] = base64.b64decode(content)
                pk_str = base64.b64encode(self.pk_ex).decode('utf-8')
                self.msg_send(socket_setup, 'NODE_KE_SE', pk_str)
                # print("Receive PK_SE from User {}.".format(user_id))
                # print(user_info)
            elif operation == 'SE_START':
                # print(user_info[user_id]['PK_SE'])
                c, k = kyber_encaps(self.user_info[user_id]['PK_SE'])
                self.user_info[user_id]['SHARED_SECRET'] = k
                c_str = base64.b64encode(c).decode('utf-8')
                # print(c_str)
                self.msg_send(socket_setup, 'SE_C', c_str, signed=True)
                u_c = u_c + 1
                # print("Sending SE_C to User {}.".format(user_id))
                # print(k)
            if u_c == self.USER_NUM:
                break
        
        
        self.KE_DONE = True
        # print("User Key/Shared Secret Exchange Complete.")
        # print("Setup Done.")

    def masking_precomputing(self):
        start_time = time.time()
        iter_num = 5
        for remote_id in self.user_info:
            if 'SHARED_SECRET' in self.user_info[remote_id]:
                x_a = self.user_info[remote_id]['SHARED_SECRET']
                if 'MASKINGS' not in self.user_info[remote_id]:
                    self.user_info[remote_id]['MASKINGS'] = {}
                for t in range(0, iter_num):
                    x_a_prf = self.gen_at(x_a, t, self.VEC_LEN)
                    self.user_info[remote_id]['MASKINGS'][t] = x_a_prf
        end_time = time.time()
        print("{} masking_precomputing time = {}".format(self.asnode_id, end_time - start_time))


    def masking_updates(self, socket):
        # print("Masking Update Start.")
        # print("Listerning ...")
        self.socket_update = socket
        u_c = 0
        
        start_time = -1
        
        while True:
            try:
                operation, user_id, content = self.msg_recv(socket)
            except zmq.Again as e:
                # print("Receiving timed out.")
                if u_c >= self.USER_NUM - 2:
                    # print("Masking Update Done.")
                    break
                else:
                    exit()
            if start_time == -1:
                start_time = time.time()
            if user_id not in self.user_info:
                print("ERROR")
            if operation == 'USER_MASK_UPDATE':
                content_list = ast.literal_eval(content)
                self.user_info[user_id]['T'] = np.array(content_list)[0] # np.fromstring(content, dtype=int, sep=' ')[0]
                # t = self.user_info[user_id]['T']
                u_c = u_c + 1
                # print("Receive USER_MASK_UPDATE from User {}.".format(user_id))
                if self.iter_num != int(self.user_info[user_id]['T']):
                    print("Iteration Numer from User {} is not correct: receive {} but should be {}.".format(user_id, self.user_info[user_id]['T'], self.iter_num))
            if u_c >= self.USER_NUM:
                # print(u_c)
                break
        
        end_time = time.time()
        print("{} masking_updates: {}".format(self.asnode_id, end_time - start_time))
        # print("Masking Update Done.")
        # # print(t)
        # # print(type(t))
        # return int(t)
        return u_c

    def aggregation_updates(self, context, server_host, server_port, user_count, precomputing):
        # print("Aggregation Update Start.")
        start_time = time.time()
        a_t = np.zeros(self.VEC_LEN)
        # print(time.time())
        if precomputing:
            for remote_id in self.user_info:
                if 'SHARED_SECRET' in self.user_info[remote_id]:
                    a_t = a_t + self.user_info[remote_id]['MASKINGS'][self.iter_num]
        else:
            for remote_id in self.user_info:
                if 'SHARED_SECRET' in self.user_info[remote_id]:
                    x_a = self.user_info[remote_id]['SHARED_SECRET']
                    x_a_prf = self.gen_at(x_a, self.iter_num, self.VEC_LEN)
                    a_t = a_t + x_a_prf
        
        # print(time.time())
        a_t = a_t.astype(int)
        m = a_t
        m = np.insert(m, 0, self.iter_num)
        m = np.insert(m, 1, user_count)
        end_time = time.time()
        print("{} aggregation_updates vector: {}".format(self.asnode_id, end_time - start_time))
        
        if 'PULL_SOCKET' in self.server_info:
            socket = self.server_info['PULL_SOCKET']
        else:
            socket = context.socket(zmq.PUSH)
            self.server_info['AGG_ADDRESS'] = "{}:{}".format(server_host, server_port)
            # print("{}:{}".format(server_host, server_port))
            socket.connect(self.server_info['AGG_ADDRESS'])
            self.server_info['PULL_SOCKET'] = socket
        msg = np.array2string(m, separator=', ', threshold=np.inf)
        self.msg_send(socket, 'NODE_MASK_UPDATE', msg)
        self.iter_num = self.iter_num + 1
        
        end_time = time.time()
        print("{} aggregation_updates: {}".format(self.asnode_id, end_time - start_time))
        # print("Sending Masking Update to Server.")
        # print("Sending Masking Update to Server: {}".format(msg))
        # print("Aggregation Update Done.")

    def aggregation_phase(self, context, server_host, server_port, socket_update, precomputing=False):
        u_c = self.masking_updates(socket_update)
        self.aggregation_updates(context, server_host, server_port, u_c, precomputing)


    def preparing(self):
        self.pk_sign, self.sk_sign = gen_pk("Dili")
        self.pk_ex, self.sk_ex = gen_pk("Kyber")
        
        Dilithium2.precomputing(self.sk_sign, self.N_SIGN * 100)

    def run_asnode(self, server_host, server_ports):
        
        context = zmq.Context()
        
        socket_setup = context.socket(zmq.REP)
        socket_setup.bind("{}:{}".format(self.host, self.port_setup))
        
        
        socket_update = context.socket(zmq.PULL)
        socket_update.setsockopt(zmq.RCVTIMEO, 80000)
        socket_update.bind("{}:{}".format(self.host, self.port_update))
        
        print("Listerning ...")
        
        """
        PQ-FL Setup Phase
        """
        print("====================== Setup Phase ======================")
        self.setup_phase(context, server_host, server_ports[0], socket_setup)
        print("=========================================================\n\n")
        
        
        self.masking_precomputing()
        
        """
        PQ-FL Aggregation Phase
        """
        print("====================== Aggregation Phase ======================")
        self.aggregation_phase(context, server_host, server_ports[1], socket_update, precomputing=True)



"""
Do not using Python Multithreading
"""
asnode_id = sys.argv[1]

host = "tcp://*"
server_host = "tcp://localhost"
server_ports = [5500, 5501]


port_setup = 5600 + (int(asnode_id)-101) * 10
# asnode_id = str(asnode_id)
node = AssistingNode(asnode_id, host, port_setup, port_setup + 1)
node.preparing()
node.run_asnode(server_host, server_ports)



"""
Using Python Multithreading
"""

# # asnode_id = sys.argv[1]
# # port_setup = int(sys.argv[2])
# host = "tcp://*"
# # ports = []
# # ports.append(int(init_port))
# # ports.append(int(init_port)+1)
# # ports.append(int(init_port)+2)
# # ports = [5600, 5601, 5602]
# server_host = "tcp://localhost"
# server_ports = [5500, 5501]

# init_id = 101
# init_asnode_port = 5600
# threads = []
# nodes = []
# start_time = time.time()
# for i in range(0, 10):
#     print(init_asnode_port)
#     port_setup = init_asnode_port
#     asnode_id = str(init_id)
#     node = AssistingNode(asnode_id, host, port_setup, port_setup + 1)
#     node.preparing()
#     nodes.append(node)
#     init_id = init_id + 1
#     init_asnode_port = init_asnode_port + 10

# end_time = time.time()
# print("Preparing Time: {}".format(end_time - start_time))

# for i in range(0, 10):
#     node = nodes[i]
#     t = threading.Thread(target=node.run_asnode, args=(server_host, server_ports,))
#     threads.append(t)
#     t.start()
#     # node.run_asnode(server_host, server_ports)

# for t in threads:
#     t.join()

# print("All threads have finished.")
