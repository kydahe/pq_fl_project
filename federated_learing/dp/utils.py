from opacus import PrivacyEngine
import torch
from torchvision import datasets, transforms
from torch.utils.data import DataLoader
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm

import zmq
import json
import os
import sys

import time
import random
import base64
import numpy as np
import ast

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
    seed_msg = bytes("Message is {}".format(random_number).encode('UTF-8'))
    
    # seed_msg = bytes("{}".format(random_number).encode('UTF-8'))
    # cipher = AES.new(b"seed_msg", AES.MODE_CTR, use_aesni='True')
    # r = cipher.encrypt(seed_msg)
    
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

def dili_sign(msg, sk, i=0, N=50):
    sig, _, __ = Dilithium2.sign_precomputed_only(sk, msg, N, N*i)
    return sig

def dili_verify(msg, sig, pk):
    ver = Dilithium2.verify_precomputed(pk, msg, sig)
    if ver == False:
        print("verify result = {}".format(ver)) 
    return ver

def kyber_encaps(pk):
    c, key = Kyber1024.enc(pk)
    return c, key

def kyber_decaps(sk, c):
    key = Kyber1024.dec(c, sk)
    return key


def message_size(m):
    total_size = sum(sys.getsizeof(item) for item in m)
    total_size_kb = total_size / 1024
    print(f"Total length: {len(m)}, size: {total_size} bytes, or {total_size_kb} KB")


def get_gradients(model):
    gradients = {name: param.grad for name, param in model.named_parameters()}
    # for name, param in model.named_parameters():
    #     print(name)
    #     print(param.grad.clone())
    #     print(param.grad.clone().shape)
    #     break
    return gradients

def get_parameters(model):
    params = {name: param for name, param in model.named_parameters()}
    # for name, param in model.named_parameters():
    #     print(name)
    #     print(param.grad.clone())
    #     print(param.grad.clone().shape)
    #     break
    return params

def gradients_to_np_array(gradients):
    mid_gradients = {}
    flat_gradients = []
    for name, grad in gradients.items():
        grad = grad.cpu()
        flat_grad = torch.flatten(grad)
        grad_np = flat_grad.numpy()
        mid_gradients[name] = grad_np
    flat_gradients = np.concatenate([arr for arr in mid_gradients.values()])
    return flat_gradients, mid_gradients


def get_shape(model, gradients):
    original_shapes = {}
    for name, param in model.named_parameters():
        original_shapes[name] = [param.grad.shape, len(gradients[name])]
    return original_shapes

def np_array_to_gradients(flat_gradients, original_shapes, device='cuda:0'):
    gradients = {}
    i = 0
    for name in original_shapes:
        original_shape = original_shapes[name][0]
        shape_len = original_shapes[name][1]
        grad_np = flat_gradients[i: i+shape_len]
        param_grad_flat = torch.from_numpy(grad_np)
        param_grad = param_grad_flat.reshape(original_shape)
        gradients[name] = param_grad.to(device)
        i = i+shape_len
    return gradients

def compare_tensor_dicts(dict1, dict2):
    # check keys
    if dict1.keys() != dict2.keys():
        return False
    # check values
    for key in dict1:
        if not torch.equal(dict1[key], dict2[key]):
            return False
    return True