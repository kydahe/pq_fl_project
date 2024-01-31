from ascon import *
import hashlib
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# SHA 128

def test_hash():
    message = b"Your message to be signed." * 5000
    print("Message Len: {}".format(len(message)))
    
    start_time = time.time()
    sha_digest = hashlib.sha256(message).hexdigest()
    end_time = time.time()
    print("SHA-256 Len: {}, Time: {}".format(len(sha_digest), round(end_time - start_time, 4)))
    
    # assert variant in ["Ascon-Xof", "Ascon-Hash", "Ascon-Xofa", "Ascon-Hasha"]
    # print("================== ASCON Hash ==================")
    variant="Ascon-Hash"
    hashlength = 32
    start_time = time.time()
    tag = ascon_hash(message, variant, hashlength)
    end_time = time.time()
    print("ASCON-Hash Len: {}, Time: {}".format(len(tag), round(end_time - start_time, 4)))

    # demo_print([("message", message), ("tag", tag)])
    # sha256_hash = hashlib.sha256(message)
    # print(tag.hex())
    # print(sha256_hash.hexdigest())
    
    # print("================== ASCON Hasha ==================")
    variant="Ascon-Hasha"
    hashlength = 32
    start_time = time.time()
    tag = ascon_hash(message, variant, hashlength)
    end_time = time.time()
    print("ASCON-Hasha Len: {}, Time: {}".format(len(tag), round(end_time - start_time, 4)))
    # print("Time: {}".format(round(end_time - start_time, 4)))

    # demo_print([("message", message), ("tag", tag)])
    
    # print("================== ASCON Xofa ==================")
    variant="Ascon-Xofa"
    hashlength = 32 # 256
    start_time = time.time()
    tag = ascon_hash(message, variant, hashlength)
    end_time = time.time()
    print("ASCON-Xofa Len: {}, Time: {}".format(len(tag), round(end_time - start_time, 4)))
    # print("Time: {}".format(round(end_time - start_time, 4)))

    # demo_print([("message", message), ("tag", tag)])
    
    # print("================== ASCON Xof ==================")
    variant="Ascon-Xof"
    hashlength = 32 # 256
    start_time = time.time()
    tag = ascon_hash(message, variant, hashlength)
    end_time = time.time()
    print("ASCON-Xof Len: {}, Time: {}".format(len(tag), round(end_time - start_time, 4)))
    # print("Time: {}".format(round(end_time - start_time, 4)))

    # demo_print([("message", message), ("tag", tag)])


def test_aead():
    plaintext = b"Your message to be encrypted/decrypted." * 800
    associateddata = b"ASCON"
    print("Message Len: {}".format(len(plaintext)))
    
    key_aes = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv), backend=default_backend())
    
    encryptor = cipher.encryptor()
    start_time = time.time()
    ct_aes = encryptor.update(plaintext) + encryptor.finalize()
    end_time = time.time()
    enc_time = end_time - start_time
    
    decryptor = cipher.decryptor()
    start_time = time.time()
    pt_aes = decryptor.update(ct_aes) + decryptor.finalize()
    end_time = time.time()
    dec_time = end_time - start_time
    print("AES-256 Key Len: {}, Encrypt Time: {}, Decrypt Time: {}".format(len(key_aes), round(enc_time, 4), round(dec_time, 4)))
    
    if pt_aes != plaintext:
        print("decryption failed!")
    
    # assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    # print("================== ASCON Ascon-128 ==================")
    variant = "Ascon-128"
    keysize = 20 if variant == "Ascon-80pq" else 16

    # choose a cryptographically strong random key and a nonce that never repeats for the same key:
    key   = get_random_bytes(keysize) # zero_bytes(keysize)
    nonce = get_random_bytes(16)      # zero_bytes(16)

    start_time = time.time()
    ciphertext        = ascon_encrypt(key, nonce, associateddata, plaintext,  variant)
    end_time = time.time()
    enc_time = end_time - start_time
    
    start_time = time.time()
    receivedplaintext = ascon_decrypt(key, nonce, associateddata, ciphertext, variant)
    end_time = time.time()
    dec_time = end_time - start_time
    print("ASCON-128 Key Len: {}, Encrypt Time: {}, Decrypt Time: {}".format(len(key), round(enc_time, 4), round(dec_time, 4)))

    if receivedplaintext == None: 
        print("verification failed!")
    # else:
    #     print("verification success!")
        
    # demo_print([("key", key), 
    #             ("nonce", nonce), 
    #             ("plaintext", plaintext), 
    #             ("ass.data", associateddata), 
    #             ("ciphertext", ciphertext[:-16]), 
    #             ("tag", ciphertext[-16:]), 
    #             ("received", receivedplaintext), 
    #            ])
    
    # print("================== ASCON Ascon-128a ==================")
    variant = "Ascon-128a"
    keysize = 20 if variant == "Ascon-80pq" else 16

    # choose a cryptographically strong random key and a nonce that never repeats for the same key:
    key   = get_random_bytes(keysize) # zero_bytes(keysize)
    nonce = get_random_bytes(16)      # zero_bytes(16)

    start_time = time.time()
    ciphertext        = ascon_encrypt(key, nonce, associateddata, plaintext,  variant)
    end_time = time.time()
    enc_time = end_time - start_time
    # print("Encryption Time: {}".format(round(end_time - start_time, 4)))
    
    start_time = time.time()
    receivedplaintext = ascon_decrypt(key, nonce, associateddata, ciphertext, variant)
    end_time = time.time()
    dec_time = end_time - start_time
    print("ASCON-128a Key Len: {}, Encrypt Time: {}, Decrypt Time: {}".format(len(key), round(enc_time, 4), round(dec_time, 4)))
    # print("Decryption Time: {}".format(round(end_time - start_time, 4)))

    if receivedplaintext == None: 
        print("verification failed!")
    # else:
    #     print("verification success!")
        
    # demo_print([("key", key), 
    #             ("nonce", nonce), 
    #             ("plaintext", plaintext), 
    #             ("ass.data", associateddata), 
    #             ("ciphertext", ciphertext[:-16]), 
    #             ("tag", ciphertext[-16:]), 
    #             ("received", receivedplaintext), 
    #            ])
    
    # print("================== ASCON Ascon-80pq ==================")
    variant = "Ascon-80pq"
    keysize = 20 if variant == "Ascon-80pq" else 16

    # choose a cryptographically strong random key and a nonce that never repeats for the same key:
    key   = get_random_bytes(keysize) # zero_bytes(keysize)
    nonce = get_random_bytes(16)      # zero_bytes(16)

    start_time = time.time()
    ciphertext        = ascon_encrypt(key, nonce, associateddata, plaintext,  variant)
    end_time = time.time()
    enc_time = end_time - start_time
    # print("Encryption Time: {}".format(round(end_time - start_time, 4)))
    
    start_time = time.time()
    receivedplaintext = ascon_decrypt(key, nonce, associateddata, ciphertext, variant)
    end_time = time.time()
    dec_time = end_time - start_time
    print("ASCON-80pq Key Len: {}, Encrypt Time: {}, Decrypt Time: {}".format(len(key), round(enc_time, 4), round(dec_time, 4)))
    # print("Decryption Time: {}".format(round(end_time - start_time, 4)))

    if receivedplaintext == None: 
        print("verification failed!")
    # else:
    #     print("verification success!")
        
    # demo_print([("key", key), 
    #             ("nonce", nonce), 
    #             ("plaintext", plaintext), 
    #             ("ass.data", associateddata), 
    #             ("ciphertext", ciphertext[:-16]), 
    #             ("tag", ciphertext[-16:]), 
    #             ("received", receivedplaintext), 
    #            ])


def test_prf():
    keysize = 16
    key   = get_random_bytes(keysize)
    nonce = get_random_bytes(16) 
    variant = "Ascon-Prf"
    
    start_time = time.time()
    r        = ascon_mac(key, nonce,  variant, taglength=32)
    end_time = time.time()
    prf_time = end_time - start_time
    print(r.hex())
    print("Time: {}".format(prf_time))
    
    

# print("================ Hash Tests ================")
# test_hash()
# print("================ Enc Tests ================")
# test_aead()

test_prf()