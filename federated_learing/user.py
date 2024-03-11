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


from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS


# asnode_info = {}

# server_info = {}

# N = 50
# NODE_NUM = 2

# User Client

class UserClient:
    def __init__(self, user_id):
        self.server_info = {}
        self.asnode_info = {}
        self.N_SIGN = 50
        self.NODE_NUM = 10
        self.VEC_LEN = 16000
        self.sk_sign = b''
        self.pk_sign = b''
        self.sk_ex = b''
        self.pk_ex = b''
        self.user_id = user_id
        self.sign_count = 0
        self.KE_DONE = False
        self.iter_num = 0
        # self.precomputed_masking = {}
    
    def generate_vector(self):
        # r = gen_r()[:4]
        # print(type(r))
        # print(r)
        # print(len(r))
        # print(bytes_to_int(r))
        w_arr = [bytes_to_int(gen_r()[:4]) for _ in range(self.VEC_LEN)]
        w = np.array(w_arr)
        return w
    
    def gen_at(self, x_a, t, length=16):
        # TODO: precomputation between setup and collection
        start_time = time.time()
        t_bytes = t.to_bytes(4, byteorder='big')
        a_t_bytes = ascon_mac(x_a[0:16], t_bytes, "Ascon-Prf", length)
        # print("bytes len {}".format(len(a_t_bytes)))
        a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
        # print(len(a_t))
        
        # nonce_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        # chacha_algo = ChaCha20.new(key=x_a[0:32], nonce=nonce_bytes)
        # data = t_bytes
        # a_t_bytes = chacha_algo.encrypt(data) *4000
        # a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
        
        print("gen_at time: {}".format(time.time()-start_time))
        return a_t


    def msg_send_with_sig(self, socket, operation, content, sig):
        msg = {'type': operation, 'session_id': self.user_id, 'content': content, 'sig': sig}
        socket.send_json(msg)

    def msg_recv_with_sig(self, resp):
        operation = resp.get('type')
        session_id = resp.get('session_id')
        content = resp.get('content')
        sig = resp.get('sig')
        return operation, session_id, content, sig

    def msg_send_no_sig(self, socket, operation, content):
        msg = {'type': operation, 'session_id': self.user_id, 'content': content}
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
            msg = {'type': operation, 'session_id': self.user_id, 'content': content}
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
            if session_id in self.asnode_info:
                pk_d = self.asnode_info[session_id]['PK_SIGN']
            elif session_id in self.server_info:
                pk_d = self.server_info[session_id]['PK_SIGN']
            sig_bytes = base64.b64decode(sig)
            ver = dili_verify(str(msg).encode('utf-8'), sig_bytes, pk_d)
            return operation, session_id, content


    def setup_phase(self, context, asnodes, node_aggs, server, server_agg, server_broad):
        
        
        # Connecting to Server
        # print("Connecting to Server ...")
        socket = context.socket(zmq.REQ)
        socket.connect(server)

        # Exchange Public Key with server
        pk_str = base64.b64encode(self.pk_sign).decode('utf-8')
        self.msg_send(socket, 'USER_KE_SIGN', pk_str)
        operation, server_id, content = self.msg_recv(socket)
        if server_id not in self.server_info:
            self.server_info[server_id] = {}
        self.server_info[server_id]['SETUP_ADDRESS'] = server
        self.server_info[server_id]['AGG_ADDRESS'] = server_agg
        self.server_info[server_id]['BROAD_ADDRESS'] = server_broad
        # asnode_info[server_id]['SOCKET'] = socket
        if operation == 'KE_SIGN':
            pk_bytes = base64.b64decode(content)
            self.server_info[server_id]['PK_SIGN'] = pk_bytes
        
        # print("Server Key Exchange Complete.")
        
        i = 0
        # Round 1
        # Connecting to assisting nodes
        for i in range(0, len(asnodes)):
            # host, port = asnode
            node = asnodes[i]
            # print("Connecting to Assisting Nodes {} ...".format(node))
            socket = context.socket(zmq.REQ)
            socket.connect(node)

            # Exchange Public Key with asnode
            pk_str = base64.b64encode(self.pk_sign).decode('utf-8')
            self.msg_send(socket, 'USER_KE_SIGN', pk_str)
            operation, asnode_id, content = self.msg_recv(socket)
            if asnode_id not in self.asnode_info:
                self.asnode_info[asnode_id] = {}
            self.asnode_info[asnode_id]['SETUP_ADDRESS'] = node
            self.asnode_info[asnode_id]['AGG_ADDRESS'] = node_aggs[i]
            if operation == 'NODE_KE_SIGN':
                pk_bytes = base64.b64decode(content)
                self.asnode_info[asnode_id]['PK_SIGN'] = pk_bytes
            
            pk_str = base64.b64encode(self.pk_ex).decode('utf-8')
            self.msg_send(socket, 'USER_KE_SE', pk_str)
            operation, asnode_id, content = self.msg_recv(socket)
            if operation == 'NODE_KE_SE':
                pk_bytes = base64.b64decode(content)
                self.asnode_info[asnode_id]['PK_SE'] = pk_bytes
            
            # print("Assiting Nodes Key Exchange Complete.")
            
            # print(asnode_info)

            # Secret Exchange
            self.msg_send(socket, 'SE_START', "SE_START", signed=True)
            operation, asnode_id, content = self.msg_recv(socket)
            if operation == 'SE_C':
                c_bytes = base64.b64decode(content)
                # print(content)
                shared_secret = kyber_decaps(self.sk_ex, c_bytes)
                self.asnode_info[asnode_id]['SHARED_SECRET'] = shared_secret
                # print(shared_secret)
            # print("Shared Secret Exchange Complete.")
        
        
        self.KE_DONE = True
        
        # print("Setup Done.")
        
    def masking_precomputing(self):
        iter_num = 5
        for remote_id in self.asnode_info:
            if 'SHARED_SECRET' in self.asnode_info[remote_id]:
                x_a = self.asnode_info[remote_id]['SHARED_SECRET']
                if 'MASKINGS' not in self.asnode_info[remote_id]:
                    self.asnode_info[remote_id]['MASKINGS'] = {}
                for t in range(0, iter_num):
                    x_a_prf = self.gen_at(x_a, t, self.VEC_LEN)
                    self.asnode_info[remote_id]['MASKINGS'][t] = x_a_prf


        
    def masking_updates(self, context, w):
        start_time = time.time()
        a_t = np.zeros(self.VEC_LEN)
        # print(time.time())
        for remote_id in self.asnode_info:
            if 'SHARED_SECRET' in self.asnode_info[remote_id]:
                x_a = self.asnode_info[remote_id]['SHARED_SECRET']
                # x_a_prf = self.gen_at(x_a, self.iter_num, len(w))
                x_a_prf = self.asnode_info[remote_id]['SHARED_SECRET'][self.iter_num]
                a_t = a_t + x_a_prf
        
        # print(time.time())
        a_t = a_t.astype(int)
        # print(w)
        # print(a_t.dtype)
        # print(w.dtype)
        y_t = w + a_t
        
        y_t = y_t.astype(int)
        m = np.insert(y_t, 0, self.iter_num)
        m_1 = np.array([self.iter_num])
        
        end_time = time.time()
        print("{} masking_updates vector: {}".format(self.user_id, end_time - start_time))
        
        for remote_id in self.asnode_info:
            if 'PULL_SOCKET' in self.asnode_info[remote_id]:
                socket = self.asnode_info[remote_id]['PULL_SOCKET']
            else:
                socket = context.socket(zmq.PUSH)
                socket.connect(self.asnode_info[remote_id]['AGG_ADDRESS'])
                self.asnode_info[remote_id]['PULL_SOCKET'] = socket
            msg = np.array2string(m_1, separator=', ', threshold=np.inf)
            self.msg_send(socket, 'USER_MASK_UPDATE', msg)
            # print("Sending Masking Update to Asnode {}: {}".format(remote_id, msg))
        
        end_time = time.time()
        print("{} masking_updates asnode done: {}".format(self.user_id, end_time - start_time))
        for server_id in self.server_info:
        #     if 'PULL_SOCKET' in self.server_info[server_id]:
        #         socket = self.server_info[server_id]['PULL_SOCKET']
        #     else:
            socket = context.socket(zmq.PUSH)
            socket.connect(self.server_info[server_id]['AGG_ADDRESS'])
            self.server_info[server_id]['PULL_SOCKET'] = socket
            msg = np.array2string(m, separator=', ', threshold=np.inf)
            self.msg_send(socket, 'USER_MASK_UPDATE', msg)
        
        end_time = time.time()
        print("{} masking_updates: {}".format(self.user_id, end_time - start_time))
        # print("Sending Masking Update to Server: {}".format(msg))
        # print("Masking Update Done.")


    def aggregation_updates(self, context):
        start_time = time.time()
        for server_id in self.server_info:
            if 'SUB_SOCKET' in self.server_info[server_id]:
                socket = self.server_info[server_id]['SUB_SOCKET']
            else:
                
                # print("Connecting to Server ...")
                socket = context.socket(zmq.SUB)
                # print(server_info[server_id]['BROAD_ADDRESS'])
                socket.connect(self.server_info[server_id]['BROAD_ADDRESS'])
                socket.setsockopt(zmq.SUBSCRIBE, b'')
                self.server_info[server_id]['SUB_SOCKET'] = socket
            
            operation, remote_id, content = self.msg_recv(socket)
            # print(content)
            if operation == 'SERVER_AGGR_BROAD':
                content_list = ast.literal_eval(content)
                w_f = np.array(content_list)
                # w_f = np.fromstring(content, dtype=int, sep=' ')
                # print(w_f)
                # print("Aggregation Complete.")
        
        self.iter_num = self.iter_num + 1
        
        
        end_time = time.time()
        print("{} aggregation_updates: {}".format(self.user_id, end_time - start_time))
        # print("Aggregation Update Done.")

    def aggregation_phase(self, context, w):
        self.masking_updates(context, w)
        # time.sleep(10)
        self.aggregation_updates(context)

    def preparing(self):
        self.pk_sign, self.sk_sign = gen_pk("Dili")
        self.pk_ex, self.sk_ex = gen_pk("Kyber")
        
        Dilithium2.precomputing(self.sk_sign, self.N_SIGN*100)

    def run_client(self, host, asnode_ports, server_ports, w):
        print("run client {}".format(self.user_id))
        
        
        context = zmq.Context()
        
        node_setups = []
        node_aggs = []
        for i in range(0, self.NODE_NUM):
            node_setups.append("{}:{}".format(host, asnode_ports[i][0]))
            node_aggs.append("{}:{}".format(host, asnode_ports[i][1]))
        server_setup = "{}:{}".format(host, server_ports[0])
        server_agg = "{}:{}".format(host, server_ports[1])
        server_broad = "{}:{}".format(host, server_ports[2])
        
        
        """
        PQ-FL Setup phase
        """
        print("====================== Setup Phase ======================")
        self.setup_phase(context, node_setups, node_aggs, server_setup, server_agg, server_broad)
        print("=========================================================\n\n")
        
        # time.sleep(10)
        self.masking_precomputing()
        
        """
        PQ-FL Aggregation phase
        """
        print("====================== Aggregation Phase ======================")
        self.aggregation_phase(context, w)



"""
Do not using Python Multithreading
"""
user_id = sys.argv[1]
asnode_ports = [[5600, 5601, 5602], [5610, 5611, 5612],
                [5620, 5621, 5622], [5630, 5631, 5632],
                [5640, 5641, 5642], [5650, 5651, 5652],
                [5660, 5661, 5662], [5670, 5671, 5672],
                [5680, 5681, 5682], [5690, 5691, 5692]]


server_ports = [5500, 5501, 5502]
# server = "tcp://localhost:5500"
host = "tcp://localhost"

node = UserClient(user_id)
node.preparing()

w = node.generate_vector()
node.run_client(host, asnode_ports, server_ports, w)

"""
Using Python Multithreading
"""

# # user_id = sys.argv[1]
# host = "tcp://localhost"
# # asnode_ports = [[5600, 5601, 5602], [5610, 5611, 5612]]
# # asnode_ports = [[5600, 5601, 5602]]
# asnode_ports = []
# server_ports = [5500, 5501, 5502]
# server = "tcp://localhost:5500"
# user_id = 1

# init_asnode_port = 5600
# threads = []
# nodes = []
# vectors = []
# for i in range(0, 10):
#     ports = [init_asnode_port, init_asnode_port +1, init_asnode_port+2]
#     asnode_ports.append(ports)
#     init_asnode_port = init_asnode_port + 10


# start_time = time.time()
# for i in range(0, 10):
#     print(user_id)
#     node = UserClient(str(user_id))
#     # node.run_client(host, asnode_ports, server_ports)
#     node.preparing()
#     w = node.generate_vector()
#     nodes.append(node)
#     vectors.append(w)
#     user_id = user_id + 1


# end_time = time.time()
# print("Preparing Time: {}".format(end_time - start_time))


# for i in range(0, 10):
#     node = nodes[i]
#     w = vectors[i]
#     t = threading.Thread(target=node.run_client, args=(host, asnode_ports, server_ports, w,))
#     threads.append(t)
#     t.start()

# for t in threads:
#     t.join()

# print("All threads have finished.")