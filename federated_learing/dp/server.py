import zmq
import json
import os
import sys
from utils import *
import time
import random
import base64
import numpy as np
import ast
from threading import Thread

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parent_dir = os.path.dirname(parent_dir)
# print(parent_dir)
sys.path.insert(0, parent_dir)
sys.path.insert(0, parent_dir+"/dilithium_py")
# original_cwd = os.getcwd()
os.chdir(parent_dir+"/dilithium_py")
from dilithium_py.dilithium import *
sys.path.insert(0, parent_dir+"/pyascon")
# original_cwd = os.getcwd()
os.chdir(parent_dir+"/pyascon")
from ascon import *
sys.path.insert(0, parent_dir+"/kyber_py")
# original_cwd = os.getcwd()
os.chdir(parent_dir+"/kyber_py")
from kyber_py.kyber import *

# asnode_info = {}
# user_info = {}
# N = 50
# USER_NUM = 2
# ASNODE_NUM = 2


class Server:
    def __init__(self, server_id, host, port_setup, port_update, port_distribute):
        self.asnode_info = {}
        self.user_info = {}
        self.N_SIGN = 50
        self.USER_NUM = 2
        self.ASNODE_NUM = 2
        self.VEC_LEN = 26010
        self.sk_sign = b''
        self.pk_sign = b''
        self.server_id = server_id
        self.host = host
        self.port_setup = port_setup
        self.port_update = port_update
        self.port_distribute = port_distribute
        self.socket_setup = None
        self.socket_update = None
        self.socket_distribute = None
        self.sign_count = 0
        self.KE_DONE = False
        self.iter_num = 0
        self.messages = []

    def msg_send_with_sig(self, socket, operation, content, sig):
        msg = {'type': operation, 'session_id': self.server_id, 'content': content, 'sig': sig}
        self.messages.append(msg)
        socket.send_json(msg)

    def msg_recv_with_sig(self, resp):
        operation = resp.get('type')
        session_id = resp.get('session_id')
        content = resp.get('content')
        sig = resp.get('sig')
        return operation, session_id, content, sig

    def msg_send_no_sig(self, socket, operation, content):
        msg = {'type': operation, 'session_id': self.server_id, 'content': content}
        self.messages.append(msg)
        socket.send_json(msg)

    def msg_recv_no_sig(self, resp):
        operation = resp.get('type')
        session_id = resp.get('session_id')
        content = resp.get('content')
        return operation, session_id, content

    def msg_send(self, socket, operation, content):
        if self.KE_DONE == False:
            self.msg_send_no_sig(socket, operation, content)
        else:
            # print("sig")
            msg = {'type': operation, 'session_id': self.server_id, 'content': content}
            sig = dili_sign(str(msg).encode('utf-8'), self.sk_sign, self.sign_count)
            sig_str = base64.b64encode(sig).decode('utf-8')
            self.msg_send_with_sig(socket, operation, content, sig_str)
            self.sign_count = (self.sign_count + 1) % 50

    def msg_recv(self, socket):
        msg = socket.recv_json()
        self.messages.append(msg)
        if 'sig' not in msg:
            return self.msg_recv_no_sig(msg)
        else:
            # print("sig")
            operation, session_id, content, sig = self.msg_recv_with_sig(msg)
            msg = {'type': operation, 'session_id': session_id, 'content': content}
            if session_id in self.asnode_info:
                pk_d = self.asnode_info[session_id]['PK_SIGN']
            elif session_id in self.user_info:
                pk_d = self.user_info[session_id]['PK_SIGN']
            sig_bytes = base64.b64decode(sig)
            ver = dili_verify(str(msg).encode('utf-8'), sig_bytes, pk_d)
            return operation, session_id, content

    def setup_phase(self, socket):
        
        start_time = -1
        while True:
            operation, remote_id, content = self.msg_recv(socket)
            if operation == 'USER_KE_SIGN':
                if remote_id not in self.user_info:
                    self.user_info[remote_id] = {}
                self.user_info[remote_id]['PK_SIGN'] = base64.b64decode(content)
                # print("Receive PK_SIGN from User {}.".format(remote_id))
                if start_time == -1:
                    start_time = time.time()
            elif operation == 'NODE_KE_SIGN':
                if remote_id not in self.asnode_info:
                    self.asnode_info[remote_id] = {}
                self.asnode_info[remote_id]['PK_SIGN'] = base64.b64decode(content)
                # print("Receive PK_SIGN from Assisting Node {}.".format(remote_id))
                
            pk_str = base64.b64encode(self.pk_sign).decode('utf-8')
            self.msg_send(socket, 'KE_SIGN', pk_str)
            if len(self.user_info) == self.USER_NUM and len(self.asnode_info) == self.ASNODE_NUM:
                break
        self.KE_DONE = True
        self.socket_setup = socket
        end_time = time.time()
        print("Setup Done: {}.".format(end_time - start_time))


    def masking_updates(self, socket):
        user_updates = []
        node_updates = []
        # start_time = time.time()
        u_c = 0
        n_c = 0
        n_u_c = -1
        
        # start_time = time.time()
        # def check_timeout():
        #     nonlocal u_c
        #     while u_c < self.USER_NUM and n_c < self.ASNODE_NUM:
        #         # if n_c == 1:
        #         #     start_time = time.time()
        #         print(u_c)
        #         print(time.time() - start_time)
        #         if time.time() - start_time > 20:
        #             if u_c > self.USER_NUM - 2 and n_c == self.ASNODE_NUM:
        #                 if n_u_c != len(user_updates):
        #                     print("User Number is not matched: receive {} but should be {}.".format(len(user_updates), n_u_c))
        #                 self.socket_update = socket
        #                 print("Masking Update Done.")
        #                 return user_updates, node_updates
        #             else:
        #                 exit() 
        #         time.sleep(1) 

        # timeout_thread = Thread(target=check_timeout)
        # timeout_thread.start()
        start_time = -1
        
        while True:
            # end_time = time.time()
            # if end_time - start_time > 300:
            #     print("Masking Update Timeout.")
            #     break
            try:
                operation, remote_id, content = self.msg_recv(socket)
            except zmq.Again as e:
                print("Receiving timed out.")
                # print(u_c)
                # print(n_c)
                if u_c >= self.USER_NUM - 2 and n_c == self.ASNODE_NUM:
                    if n_u_c != len(user_updates):
                        print("User Number is not matched: receive {} but should be {}.".format(len(user_updates), n_u_c))
                    self.socket_update = socket
                    # print("Masking Update Done.")
                    return user_updates, node_updates
                else:
                    exit()
            if start_time == -1:
                start_time = time.time()
            if operation == 'USER_MASK_UPDATE':
                # print(content)
                content_list = ast.literal_eval(content)
                w_t = np.array(content_list)
                # w_t = np.fromstring(content, dtype=int, sep=' ')
                self.user_info[remote_id]['MASK_UPDATE'] = w_t
                # user_updates.append(w_t)
                u_c = u_c + 1
                # print("Receive USER_MASK_UPDATE from User {}: {}".format(remote_id, w_t))
                if self.iter_num != int(w_t[0]):
                    print("Iteration Numer from User {} is not correct: receive {} but should be {}.".format(remote_id, w_t[0], self.iter_num))
                user_updates.append(w_t[1:])
            elif operation == 'NODE_MASK_UPDATE':
                content_list = ast.literal_eval(content)
                a_t = np.array(content_list)
                # a_t = np.fromstring(content, dtype=int, sep=' ')
                self.asnode_info[remote_id]['MASK_UPDATE'] = a_t
                # node_updates.append(a_t)
                n_c = n_c + 1
                # print("Receive NODE_MASK_UPDATE from Assisting Node {}: {}".format(remote_id, a_t))
                if self.iter_num != int(a_t[0]):
                    print("Iteration Numer from Node {} is not correct: receive {} but should be {}.".format(remote_id, a_t[0], self.iter_num))
                if n_u_c == -1:
                    n_u_c = int(a_t[1])
                elif n_u_c != int(a_t[1]):
                    print("User Numer from Node {} is not correct: receive {} but should be {}.".format(remote_id, a_t[2], n_u_c))
                node_updates.append(a_t[2:])
            if u_c >= self.USER_NUM and n_c >= self.ASNODE_NUM:
                break
        if n_u_c != len(user_updates):
            print("User Number is not matched: receive {} but should be {}.".format(len(user_updates), n_u_c))
        self.socket_update = socket
        end_time = time.time()
        print("Masking Update Done: {}.".format(end_time - start_time))
        return user_updates, node_updates, end_time - start_time

    def calc_final_w(self, user_updates, node_updates):
        # check t
        # t = user_updates[0][0]
        # u_updates = []
        # for user_update in user_updates:
        #     if t != user_update[0]:
        #         print("(User) Not Same t")
        #     u_updates.append(user_update[1:])
        
        # user_count = len(user_updates)
        # n_updates = []
        # for node_update in node_updates:
        #     if t != node_update[0]:
        #         print("(Node) Not Same t")
        #     if user_count != node_update[1]:
        #         print("(Node) Not Same user_count")
        #         # print(user_count)
        #         # print(node_update[1])
        #     n_updates.append(node_update[2:])
        
        # sum up user vectors
        u_stacks = np.stack(user_updates)
        u_sum = np.sum(u_stacks, axis=0)
        
        # sum up asnode vectors
        n_stacks = np.stack(node_updates)
        n_sum = np.sum(n_stacks, axis=0)
        
        final_w = u_sum - n_sum
        return final_w
        
    def aggregate_gradients(self, client_gradients):
        aggregated_gradients = {}
        for key in client_gradients[0].keys():
            aggregated_gradients[key] = torch.mean(
                torch.stack([grads[key] for grads in client_gradients]), dim=0
            )
        return aggregated_gradients

    def aggregation_updates(self, socket, user_updates, node_updates):
        start_time = time.time()
        w = self.calc_final_w(user_updates, node_updates)
        
        end_time = time.time()
        print("Aggregation Update - calculate final vector: {}.".format(end_time - start_time))
        
        # time.sleep(10)
        msg = np.array2string(w, separator=', ', threshold=np.inf)
        self.msg_send(socket, 'SERVER_AGGR_BROAD', msg)
        self.socket_distribute = socket
        self.iter_num = self.iter_num + 1
        end_time = time.time()
        # print(w)
        # print(msg)
        print("Aggregation Update Done: {}.".format(end_time - start_time))
        return end_time - start_time
        
    def aggregation_phase(self, socket_update, socket_distribute):
        start_time = time.time()
        user_updates, node_updates, time_1 = self.masking_updates(socket_update)
        time_2 = self.aggregation_updates(socket_distribute, user_updates, node_updates)
        end_time = time.time()
        print("Aggregation Done: {} ({}).".format(time_1+time_2, end_time - start_time))

    def run_server(self):
        self.pk_sign, self.sk_sign = gen_pk("Dili")
        
        Dilithium2.precomputing(self.sk_sign, self.N_SIGN*100)
        
        context = zmq.Context()
        
        
        socket_setup = context.socket(zmq.REP)
        # socket_setup.setsockopt(zmq.RCVTIMEO, 20)
        socket_setup.bind("{}:{}".format(self.host, self.port_setup))
        
        socket_update = context.socket(zmq.PULL)
        socket_update.setsockopt(zmq.RCVTIMEO, 80000)
        print("{}:{}".format(self.host, self.port_update))
        socket_update.bind("{}:{}".format(self.host, self.port_update))
        
        socket_distribute = context.socket(zmq.PUB)
        # print("{}:{}".format(host, port))
        socket_distribute.bind("{}:{}".format(self.host, self.port_distribute))
        
        print("Listerning ...")
        
        """
        PQ-FL Setup Phase
        """
        print("====================== Setup Phase ======================")
        self.setup_phase(socket_setup)
        print("=========================================================\n\n")
        
        """
        PQ-FL Aggregation Phase
        """
        print("====================== Aggregation Phase ======================")
        self.aggregation_phase(socket_update, socket_distribute)
        
        message_size(self.messages)



host = "tcp://*"
port_setup = 5500
# ports = [5500, 5501, 5502, 5503]
server_id = 1000
server = Server(server_id, host, port_setup, port_setup+1, port_setup+2)
server.run_server()