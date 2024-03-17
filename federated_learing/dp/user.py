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
        self.NODE_NUM = 3
        self.VEC_LEN = 16000  # 26010
        self.sk_sign = b''
        self.pk_sign = b''
        self.sk_ex = b''
        self.pk_ex = b''
        self.user_id = user_id
        self.sign_count = 0
        self.KE_DONE = False
        self.iter_num = 0
        self.train_device = "cuda" if torch.cuda.is_available() else "cpu"
        self.train_delta=1e-5
        self.train_lr=0.05
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
        # start_time = time.time()
        t_bytes = t.to_bytes(4, byteorder='big')
        
        # a_t_bytes = ascon_mac(x_a[0:16], t_bytes, "Ascon-Prf", length)
        # a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
        # print("bytes len {}".format(len(a_t_bytes)))
        # print(len(a_t))
        
        cipher = AES.new(x_a[0:16], AES.MODE_CTR, use_aesni='True')
        a_t_bytes = cipher.encrypt(t_bytes)*(math.ceil(self.VEC_LEN/4))
        a_t = np.frombuffer(a_t_bytes[0:self.VEC_LEN], dtype=np.uint8)
        # print("bytes len {}".format(len(a_t_bytes)))
        # print(cipher.nonce)
        
        
        # nonce_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        # chacha_algo = ChaCha20.new(key=x_a[0:32], nonce=nonce_bytes)
        # data = t_bytes
        # a_t_bytes = chacha_algo.encrypt(data) *4000
        # a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
        
        
        
        # print("gen_at time: {}".format(time.time()-start_time))
        return a_t


    def msg_send_with_sig(self, operation, content, sig):
        msg = {'type': operation, 'session_id': self.user_id, 'content': content, 'sig': sig}
        # print("msg_send_with_sig: {}".format(time.time()))
        # socket.send_json(msg)
        return msg

    def msg_recv_with_sig(self, resp):
        operation = resp.get('type')
        session_id = resp.get('session_id')
        content = resp.get('content')
        sig = resp.get('sig')
        return operation, session_id, content, sig

    def msg_send_no_sig(self, operation, content):
        msg = {'type': operation, 'session_id': self.user_id, 'content': content}
        # socket.send_json(msg)
        return msg

    def msg_recv_no_sig(self, resp):
        operation = resp.get('type')
        session_id = resp.get('session_id')
        content = resp.get('content')
        return operation, session_id, content, 0

    def msg_send(self, operation, content, signed=False):
        if self.KE_DONE == False and signed == False:
            msg_to_sent = self.msg_send_no_sig(operation, content)
        else:
            # print("sig")
            print
            msg = {'type': operation, 'session_id': self.user_id, 'content': content}
            sig = dili_sign(str(msg).encode('utf-8'), self.sk_sign, self.sign_count)
            sig_str = base64.b64encode(sig).decode('utf-8')
            msg_to_sent = self.msg_send_with_sig(operation, content, sig_str)
            self.sign_count = (self.sign_count + 1) % 50
        return msg_to_sent

    def msg_recv(self, socket):
        msg = socket.recv_json()
        if 'sig' not in msg:
            return self.msg_recv_no_sig(msg)
        else:
            # print("sig")
            start_time = time.time()
            operation, session_id, content, sig = self.msg_recv_with_sig(msg)
            msg = {'type': operation, 'session_id': session_id, 'content': content}
            if session_id in self.asnode_info:
                pk_d = self.asnode_info[session_id]['PK_SIGN']
            elif session_id in self.server_info:
                pk_d = self.server_info[session_id]['PK_SIGN']
            sig_bytes = base64.b64decode(sig)
            ver = dili_verify(str(msg).encode('utf-8'), sig_bytes, pk_d)
            end_time = time.time()
            return operation, session_id, content, end_time - start_time

    
    def train(self, model, train_loader, optimizer, device, delta=1e-5):
        model.train()
        criterion = torch.nn.CrossEntropyLoss()
        # losses = []    
        for _batch_idx, (data, target) in enumerate(tqdm(train_loader)):
            data, target = data.to(device), target.to(device)
            optimizer.zero_grad()
            output = model(data)
            loss = criterion(output, target)
            loss.backward()
            optimizer.step()
        #     losses.append(loss.item())    
        # epsilon, best_alpha = optimizer.privacy_engine.get_privacy_spent(delta) 
        # print(
        #     f"Train Loss: {np.mean(losses):.6f}"
        #     f"(ε = {epsilon:.2f}, δ = {delta}) for α = {best_alpha}")
        
        return model, train_loader, optimizer

    def get_model(self):
        # Loading MNIST Data
        train_loader = torch.utils.data.DataLoader(datasets.MNIST('../mnist', train=True, download=True,
                    transform=transforms.Compose([transforms.ToTensor(), transforms.Normalize((0.1307,), 
                    (0.3081,)),]),), batch_size=64, shuffle=True, num_workers=1, pin_memory=True)

        test_loader = torch.utils.data.DataLoader(datasets.MNIST('../mnist', train=False, 
                    transform=transforms.Compose([transforms.ToTensor(), transforms.Normalize((0.1307,), 
                    (0.3081,)),]),), batch_size=1024, shuffle=True, num_workers=1, pin_memory=True)


        # Creating a PyTorch Neural Network Classification Model and Optimizer
        model = torch.nn.Sequential(torch.nn.Conv2d(1, 16, 8, 2, padding=3), torch.nn.ReLU(), torch.nn.MaxPool2d(2, 1),
                torch.nn.Conv2d(16, 32, 4, 2),  torch.nn.ReLU(), torch.nn.MaxPool2d(2, 1), torch.nn.Flatten(), 
                torch.nn.Linear(32 * 4 * 4, 32), torch.nn.ReLU(), torch.nn.Linear(32, 10))

        optimizer = torch.optim.SGD(model.parameters(), lr=0.05)

        # Attaching a Differential Privacy Engine to the Optimizer
        privacy_engine = PrivacyEngine()
        model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
            module=model,
            optimizer=optimizer,
            data_loader=train_loader,
            target_epsilon=8.0,
            target_delta=1e-5,
            epochs=1, 
            max_grad_norm=1.0,
        )
        
        device = torch.device(self.train_device)
        model.to(device)
        return model, optimizer, train_loader, test_loader, device
    
    
    def local_training(self, model, train_loader, optimizer, device, delta=1e-5):
        return self.train(model, train_loader, optimizer, device, delta)
    
    
    def update_model_gradients(self, model, aggregated_updates):
        for name, param in model.named_parameters():
            if name in aggregated_updates:
                # print(name)
                if param.grad is None:
                    param.grad = aggregated_updates[name]
                else:
                    param.grad.data.copy_(aggregated_updates[name])
        return model

    def update_model_parameters(self, model, lr=0.05):
        for name, param in model.named_parameters():
            # param.data.copy_(param.data - lr * param.grad)
            param.data -= lr * param.grad
        return model
        


    def setup_phase(self, context, asnodes, node_aggs, server, server_agg, server_broad):
        # Connecting to Server
        # print("Connecting to Server ...")
        socket = context.socket(zmq.REQ)
        socket.connect(server)

        # Exchange Public Key with server
        pk_str = base64.b64encode(self.pk_sign).decode('utf-8')
        msg = self.msg_send('USER_KE_SIGN', pk_str)
        socket.send_json(msg)
        operation, server_id, content, _ = self.msg_recv(socket)
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
            msg = self.msg_send('USER_KE_SIGN', pk_str)
            socket.send_json(msg)
            operation, asnode_id, content, _ = self.msg_recv(socket)
            if asnode_id not in self.asnode_info:
                self.asnode_info[asnode_id] = {}
            self.asnode_info[asnode_id]['SETUP_ADDRESS'] = node
            self.asnode_info[asnode_id]['AGG_ADDRESS'] = node_aggs[i]
            if operation == 'NODE_KE_SIGN':
                pk_bytes = base64.b64decode(content)
                self.asnode_info[asnode_id]['PK_SIGN'] = pk_bytes
            
            pk_str = base64.b64encode(self.pk_ex).decode('utf-8')
            msg = self.msg_send('USER_KE_SE', pk_str)
            socket.send_json(msg)
            operation, asnode_id, content, _ = self.msg_recv(socket)
            if operation == 'NODE_KE_SE':
                pk_bytes = base64.b64decode(content)
                self.asnode_info[asnode_id]['PK_SE'] = pk_bytes
            
            # print("Assiting Nodes Key Exchange Complete.")
            
            # print(asnode_info)

            # Secret Exchange
            msg = self.msg_send('SE_START', "SE_START", signed=True)
            socket.send_json(msg)
            operation, asnode_id, content, _ = self.msg_recv(socket)
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
        start_time = time.time()
        iter_num = 5
        for remote_id in self.asnode_info:
            if 'SHARED_SECRET' in self.asnode_info[remote_id]:
                x_a = self.asnode_info[remote_id]['SHARED_SECRET']
                if 'MASKINGS' not in self.asnode_info[remote_id]:
                    self.asnode_info[remote_id]['MASKINGS'] = {}
                for t in range(0, iter_num):
                    x_a_prf = self.gen_at(x_a, t, self.VEC_LEN)
                    self.asnode_info[remote_id]['MASKINGS'][t] = x_a_prf
        
        end_time = time.time()
        print("{} masking_precomputing time = {}".format(self.user_id, (end_time - start_time)*1000))


        
    def masking_updates(self, context, w, precomputing):
        start_time = time.time()
        a_t = np.zeros(self.VEC_LEN)
        # print(time.time())
        if precomputing:
            for remote_id in self.asnode_info:
                if 'SHARED_SECRET' in self.asnode_info[remote_id]:
                    a_t = a_t + self.asnode_info[remote_id]['SHARED_SECRET'][self.iter_num]
        else:
            for remote_id in self.asnode_info:
                if 'SHARED_SECRET' in self.asnode_info[remote_id]:
                        x_a = self.asnode_info[remote_id]['SHARED_SECRET']
                        x_a_prf = self.gen_at(x_a, self.iter_num, len(w))
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
        
        start_time_1 = time.time()
        msg_asnode = np.array2string(m_1, separator=', ', threshold=np.inf)
        msg_asnode = self.msg_send('USER_MASK_UPDATE', msg_asnode)
        
        msg_server = np.array2string(m, separator=', ', threshold=np.inf)
        msg_server = self.msg_send('USER_MASK_UPDATE', msg_server)
        
        end_time = time.time()
        print("{} masking_updates message signing: {}".format(self.user_id, (end_time - start_time_1)))
        print("{} masking_updates message construction: {}".format(self.user_id, (end_time - start_time)*1000))
        
        
        time_arr = []
        for remote_id in self.asnode_info:
            # start_time_1 = time.time()
            # print("{} masking_sending to asnode {} (start): {}".format(self.user_id, remote_id, start_time_1))
            if 'PULL_SOCKET' in self.asnode_info[remote_id]:
                socket = self.asnode_info[remote_id]['PULL_SOCKET']
            else:
                socket = context.socket(zmq.PUSH)
                socket.connect(self.asnode_info[remote_id]['AGG_ADDRESS'])
                self.asnode_info[remote_id]['PULL_SOCKET'] = socket
            socket.send_json(msg_asnode)
            # end_time_1 = time.time()
            # print("Sending Masking Update to Asnode {}: {}".format(remote_id, msg))
            # print("{} masking_sending to asnode {}: {}".format(self.user_id, remote_id, end_time_1 - start_time_1))
            # time_arr.append(end_time_1 - start_time_1)
        
        # print("{} masking_sending to asnode (average): {}".format(self.user_id, np.mean(np.array(time_arr))))
        
        
        # end_time = time.time()
        # print("{} masking_updates asnode done: {}".format(self.user_id, end_time - start_time))
        for server_id in self.server_info:
            # start_time_1 = time.time()
        #     if 'PULL_SOCKET' in self.server_info[server_id]:
        #         socket = self.server_info[server_id]['PULL_SOCKET']
        #     else:
            socket = context.socket(zmq.PUSH)
            socket.connect(self.server_info[server_id]['AGG_ADDRESS'])
            self.server_info[server_id]['PULL_SOCKET'] = socket
            socket.send_json(msg_server)
            # end_time_1 = time.time()
            # print("{} masking_sending to server: {}".format(self.user_id, end_time_1 - start_time_1))
        
        # end_time = time.time()
        # print("{} masking_updates: {}".format(self.user_id, end_time - start_time))
        # print("Sending Masking Update to Server: {}".format(msg))
        # print("Masking Update Done.")


    def aggregation_updates(self, context):
        start_time = time.time()
        update_vec = np.zeros(self.VEC_LEN)
        used_time = 0
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
            
            operation, remote_id, content, used_time = self.msg_recv(socket)
            # print(content)
            if operation == 'SERVER_AGGR_BROAD':
                content_list = ast.literal_eval(content)
                update_vec = np.array(content_list)
                # update_vec = np.fromstring(content, dtype=int, sep=' ')
                # print(update_vec)
                # print("Aggregation Complete.")
        
        self.iter_num = self.iter_num + 1
        
        
        print("{} get new update vector: {}".format(self.user_id, used_time))
        end_time = time.time()
        print("{} aggregation_updates: {}".format(self.user_id, end_time - start_time))
        # print("Aggregation Update Done.")
        return update_vec

    def aggregation_phase(self, context, w, precomputing=False):
        self.masking_updates(context, w, precomputing)
        # time.sleep(10)
        update_vec = self.aggregation_updates(context)
        return update_vec

    def preparing(self):
        self.pk_sign, self.sk_sign = gen_pk("Dili")
        self.pk_ex, self.sk_ex = gen_pk("Kyber")
        
        Dilithium2.precomputing(self.sk_sign, self.N_SIGN*100)

    def run_client(self, host, asnode_ports, server_ports, flat_gradients):
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
        # print("=========================================================\n\n")
        
        # time.sleep(10)
        self.masking_precomputing()
        
        
        # print("====================== Local Training ======================")
        # model, optimizer, train_loader, test_loader, device = self.get_model()
        # start_time = time.time()
        # model, train_loader, optimizer = self.local_training(model, train_loader, optimizer, device)
        
        # client_update_vector = get_gradients(model)
        # flat_gradients, mid_gradients = gradients_to_np_array(client_update_vector)
        # original_shapes = get_shape(model, mid_gradients)
        
        # flat_gradients = self.generate_vector()
        # print("{} Training gradient generation: {}".format(self.user_id, time.time() - start_time))
        
        
        """
        PQ-FL Aggregation phase
        """
        print("====================== Aggregation Phase ======================")
        update_vec = self.aggregation_phase(context, flat_gradients, precomputing=True)
        
        # print("====================== Update Aggregation Vector ======================")
        
        # start_time = time.time()
        # restored_gradients = np_array_to_gradients(update_vec, original_shapes, device)
        # # print(get_parameters(model))
        # model = self.update_model_gradients(model, restored_gradients)
        # model = self.update_model_parameters(model)
        # print("{} New gradient update: {}".format(self.user_id, time.time() - start_time))
        # # print(get_parameters(model))



"""
Do not using Python Multithreading
"""

def run_one_user(node, w):
    asnode_ports = [[5600, 5601, 5602], [5610, 5611, 5612],
                    [5620, 5621, 5622], [5630, 5631, 5632],
                    [5640, 5641, 5642], [5650, 5651, 5652],
                    [5660, 5661, 5662], [5670, 5671, 5672],
                    [5680, 5681, 5682], [5690, 5691, 5692]]


    server_ports = [5500, 5501, 5502]
    # server = "tcp://localhost:5500"
    host = "tcp://localhost"
    node.run_client(host, asnode_ports, server_ports, w)


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

