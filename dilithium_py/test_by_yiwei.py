import os
import sys
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)
sys.path.insert(0, parent_dir+"/dilithium_py")
original_cwd = os.getcwd()
os.chdir(parent_dir+"/dilithium_py")
from dilithium_py.dilithium import Dilithium2
import time
import string
import random
from multiprocessing import Process, Queue, cpu_count
 



# Normal 
def normal_test():
    print("================== Normal Dilithium Test ==================")
    # pk, sk = Dilithium2.keygen()
    # msg = b"Your message signed by Dilithium"
    time_list = []
    loop_list = []
    y_list = []
    w_list = []
    sig_list = []
    pk, sk = Dilithium2.keygen()
    for i in range(30):
        # pk, sk = Dilithium2.keygen()
        # msg = b"Your message signed by Dilithium" * 1000
        # msg = bytes("Your {} message signed by Dilithium {}".format(i, i).encode('UTF-8'))*10
        res = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
        # print(res)
        msg = bytes(res.encode('UTF-8')) * 10
        start_time = time.time()
        sig, loop_i, y = Dilithium2.sign(sk, msg)
        end_time = time.time()
        time_list.append(round(end_time - start_time, 4))
        loop_list.append(loop_i)
        # print("{}th msg: {}".format(i+1, msg))
        # print("In {}th while loop, get the signature".format(loop_i))
        # print("Sign Time = {}".format(round(end_time - start_time, 4)))
        
        # if y not in y_list:
        #     y_list.append(y)
        # else:
        #     print("Same Y")
        
        # # if w not in w_list:
        # #     w_list.append(w)
        # # else:
        # #     print("Same W")
        
        # if sig not in sig_list:
        #     sig_list.append(sig)
        # else:
        #     print("Same Sig")
        
        
        ver = Dilithium2.verify(pk, msg, sig)
        # print("verify result = {}".format(ver))
        # print("{}th test: Find the signature at {}th while loop with {} s.".format(i+1, loop_i, round(end_time - start_time, 4)))
        if ver != True:
            print("Signature Verify Failed")
        # print("+++++++++++++++++++++++++++++++++\n")
    print("\n+++++++++++++++++++++++++++++++++")
    print("Summary:")
    print("Loops: {}".format(len(loop_list)))
    print(loop_list)
    print("Time: {}".format(len(time_list)))
    print(time_list)
    print("Average Loops: {}".format(sum(loop_list)/len(loop_list)))
    print("Average Time: {}".format(sum(time_list)/len(time_list)))
    
def precomputed_test():
    print("================== Precomputed Dilithium Test Without Multiprocessing ==================")
    # pk, sk = Dilithium2.keygen()
    # msg = b"Your message signed by Dilithium"
    # pool = Pool(processes=48)
    time_list = []
    loop_list = []
    y_list = []
    w_list = []
    sig_list = []
    N = 50
    pk, sk = Dilithium2.keygen()
    start_time = time.time()
    Dilithium2.precomputing_only(sk, N*50)
    end_time = time.time()
    print("Precomputing time: {}".format(round(end_time - start_time, 4)))
    for i in range(30):
        # msg = b"Your message signed by Dilithium" * 1000
        # msg = bytes("Your message signed by Dilithium {}".format(i).encode('UTF-8'))*10
        res = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
        msg = bytes(res.encode('UTF-8')) * 10
        
        start_time = time.time()
        sig, loop_i, y = Dilithium2.sign_precomputed_only(sk, msg, N, N*i)
        end_time = time.time()
        time_list.append(round(end_time - start_time, 4))
        loop_list.append(loop_i)
        
        ver = Dilithium2.verify_precomputed(pk, msg, sig)
        # print("{}th test: Find the signature at {}th while loop with {} s (Total time).".format(i+1, loop_i, round(end_time - start_time, 4)))
        if ver != True:
            print("Signature Verify Failed")
    print("\n+++++++++++++++++++++++++++++++++")
    print("Summary:")
    print("Loops: {}".format(len(loop_list)))
    print(loop_list)
    print("Time: {}".format(len(time_list)))
    print(time_list)
    print("Average Loops: {}".format(sum(loop_list)/len(loop_list)))
    print("Average Time: {}".format(sum(time_list)/len(time_list)))


def precomputed_test_pmp():
    print("================== Precomputed Dilithium Test with mutiprocessing in precomputation ==================")
    # pk, sk = Dilithium2.keygen()
    # msg = b"Your message signed by Dilithium"
    # pool = Pool(processes=48)
    time_list = []
    loop_list = []
    y_list = []
    w_list = []
    sig_list = []
    N = 50
    pk, sk = Dilithium2.keygen()
    start_time = time.time()
    Dilithium2.precomputing(sk, N*50)
    end_time = time.time()
    print("Precomputing time: {}".format(round(end_time - start_time, 4)))
    MSG_NUM = 30
    for i in range(30):
        # msg = b"Your message signed by Dilithium" * 1000
        # msg = bytes("Your message signed by Dilithium {}".format(i).encode('UTF-8'))*10
        res = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
        msg = bytes(res.encode('UTF-8')) * 10
        
        start_time = time.time()
        sig, loop_i, y = Dilithium2.sign_precomputed_only(sk, msg, N, N*i)
        end_time = time.time()
        time_list.append(round(end_time - start_time, 4))
        loop_list.append(loop_i)
        
        ver = Dilithium2.verify_precomputed(pk, msg, sig)
        # print("{}th test: Find the signature at {}th while loop with {} s (Total time).".format(i+1, loop_i, round(end_time - start_time, 4)))
        if ver != True:
            print("Signature Verify Failed")
    print("\n+++++++++++++++++++++++++++++++++")
    print("Summary:")
    print("Loops: {}".format(len(loop_list)))
    print(loop_list)
    print("Time: {}".format(len(time_list)))
    print(time_list)
    print("Average Loops: {}".format(sum(loop_list)/len(loop_list)))
    print("Average Time: {}".format(sum(time_list)/len(time_list)))
    # used_params = Dilithium2.sk_params[sk]['precomputed']
    # set_used_params=[]
    # for i in used_params:
    #     if i not in set_used_params:
    #         set_used_params.append(i)
    # if len(used_params) != len(set_used_params):
    #     print("!!!!!! Use Same Params")



def precomputed_test_mp():
    print("================== Precomputed Dilithium Test with mutiprocessing in both precomputation and signning ==================")
    # pk, sk = Dilithium2.keygen()
    # msg = b"Your message signed by Dilithium"
    # pool = Pool(processes=48)
    time_list = []
    loop_list = []
    y_list = []
    w_list = []
    sig_list = []
    N = 50
    pk, sk = Dilithium2.keygen()
    start_time = time.time()
    Dilithium2.precomputing(sk, N*50)
    end_time = time.time()
    print("Precomputing time: {}".format(round(end_time - start_time, 4)))
    MSG_NUM = 30
    for i in range(30):
        # msg = b"Your message signed by Dilithium" * 1000
        # msg = bytes("Your message signed by Dilithium {}".format(i).encode('UTF-8'))*10
        res = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
        msg = bytes(res.encode('UTF-8')) * 10
        
        start_time = time.time()
        sig, loop_i, y = Dilithium2.sign_precomputed(sk, msg, N, N*i)
        end_time = time.time()
        time_list.append(round(end_time - start_time, 4))
        loop_list.append(loop_i)
        
        ver = Dilithium2.verify_precomputed(pk, msg, sig)
        # print("{}th test: Find the signature at {}th while loop with {} s (Total time).".format(i+1, loop_i, round(end_time - start_time, 4)))
        if ver != True:
            print("Signature Verify Failed")
    print("\n+++++++++++++++++++++++++++++++++")
    print("Summary:")
    print("Loops: {}".format(len(loop_list)))
    print(loop_list)
    print("Time: {}".format(len(time_list)))
    print(time_list)
    print("Average Loops: {}".format(sum(loop_list)/len(loop_list)))
    print("Average Time: {}".format(sum(time_list)/len(time_list)))
    # used_params = Dilithium2.sk_params[sk]['precomputed']
    # set_used_params=[]
    # for i in used_params:
    #     if i not in set_used_params:
    #         set_used_params.append(i)
    # if len(used_params) != len(set_used_params):
    #     print("!!!!!! Use Same Params")






def calc_sign(sk, shared_queues, messages, N, N_s):
    i = 0
    results = []
    for msg in messages:
        start_time = time.time()
        sig, loop_i, y = Dilithium2.sign_precomputed(sk, msg, N, N_s + N*i)
        end_time = time.time()
        results.append((msg, sig, loop_i, round(end_time - start_time, 4)))
        i = i+1
    shared_queues.put(results)


def precomputed_test_mp_both():
    print("================== Precomputed Dilithium Test ==================")
    # pk, sk = Dilithium2.keygen()
    # msg = b"Your message signed by Dilithium"
    # pool = Pool(processes=48)
    time_list = []
    loop_list = []
    y_list = []
    w_list = []
    sig_list = []
    N = 50
    pk, sk = Dilithium2.keygen()
    start_time = time.time()
    Dilithium2.precomputing(sk, N*50)
    end_time = time.time()
    print("Precomputing time: {}".format(round(end_time - start_time, 4)))
    MSG_NUM = 30
    messages = []
    sign_results = []
    for i in range(MSG_NUM):
        # msg = b"Your message signed by Dilithium" * 1000
        # msg = bytes("Your message signed by Dilithium {}".format(i).encode('UTF-8'))*10
        res = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
        msg = bytes(res.encode('UTF-8')) * 10
        messages.append(msg)
    
    num_processes = cpu_count()
    shared_queues = Queue()
    processes = []
    msg_num_per_process = (MSG_NUM // num_processes) + 1
    
    for i in range(num_processes):
        # start_time = time.time()
        # sig, loop_i, y = Dilithium2.sign_precomputed(sk, msg, N, N*i)
        msgs = messages[i*msg_num_per_process:(i+1)*msg_num_per_process] if (i+1)*msg_num_per_process <= MSG_NUM else msg[i*msg_num_per_process:MSG_NUM] 
        p = Process(target=calc_sign, args=(sk, shared_queues, msgs, N, N*i*msg_num_per_process))
        processes.append(p)
        p.start()
        if (i+1)*msg_num_per_process > MSG_NUM:
            break
    
    for p in processes:
        sign_results.extend(shared_queues.get())
    
    for p in processes:
        p.join()
    
    for msg, sig, loop_i, time1 in sign_results:        
        ver = Dilithium2.verify_precomputed(pk, msg, sig)
        # print("{}th test: Find the signature at {}th while loop with {} s (Total time).".format(i+1, loop_i, round(end_time - start_time, 4)))
        if ver != True:
            print("Signature Verify Failed")
        loop_list.append(loop_i)
        time_list.append(time1)
    print("\n+++++++++++++++++++++++++++++++++")
    print("Summary:")
    print("Loops: {}".format(len(loop_list)))
    print(loop_list)
    print("Time: {}".format(len(time_list)))
    print(time_list)
    print("Average Loops: {}".format(sum(loop_list)/len(loop_list)))
    print("Average Time: {}".format(sum(time_list)/len(time_list)))
    # used_params = Dilithium2.sk_params[sk]['precomputed']
    # set_used_params=[]
    # for i in used_params:
    #     if i not in set_used_params:
    #         set_used_params.append(i)
    # if len(used_params) != len(set_used_params):
    #     print("!!!!!! Use Same Params")

start = time.time()
# normal_test()
# precomputed_test()
# precomputed_test_pmp()
precomputed_test_mp()
# precomputed_test_mp_both()
end = time.time()
print("++++++++++++++++++++++++")
print("Total time: {}".format(round(end - start, 4)))


















def both_test():
    time_list = []
    loop_list = []
    y_list = []
    w_list = []
    sig_list = []
    pk, sk = Dilithium2.keygen()
    
    print("================== Normal Dilithium Test ==================")
    for i in range(20):
        # msg = b"Your message signed by Dilithium" * 1000
        res = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
        msg = bytes(res.encode('UTF-8')) * 10
        start_time = time.time()
        sig, loop_i, y = Dilithium2.sign(sk, msg)
        end_time = time.time()
        time_list.append(round(end_time - start_time, 4))
        loop_list.append(loop_i)
        # print("{}th msg: {}".format(i, msg))
        # if loop_i != 0:
        #     print("In {}th while loop, get the signature".format(loop_i))
        #     loop_list.append(loop_i)
        # else:
        #     print("precomputed!")
        #     loop_list.append(loop_i)
        # print("Sign Time = {}".format(round(end_time - start_time, 4)))
        
        # if y not in y_list:
        #     y_list.append(y)
        # else:
        #     print("Same Y")
        
        # # if w not in w_list:
        # #     w_list.append(w)
        # # else:
        # #     print("Same W")
        
        # if sig not in sig_list:
        #     sig_list.append(sig)
        # else:
        #     print("Same Sig")
        
        
        ver = Dilithium2.verify(pk, msg, sig)
        # print("{}th test: Find the signature at {}th while loop with {} s.".format(i+1, loop_i, round(end_time - start_time, 4)))
        if ver != True:
            print("Signature Verify Failed")
        # print("+++++++++++++++++++++++++++++++++\n")
    print("\n+++++++++++++++++++++++++++++++++")
    print("Summary:")
    print("Loops: {}".format(len(loop_list)))
    print(loop_list)
    print("Time: {}".format(len(time_list)))
    print(time_list)
    print("Average Loops: {}".format(sum(loop_list)/len(loop_list)))
    print("Average Time: {}".format(sum(time_list)/len(time_list)))
    avg_normal = sum(time_list)/len(time_list)
    
    
    print("================== Precomputed Dilithium Test ==================")
    time_list = []
    loop_list = []
    Dilithium2.pre_computed(sk, 100)
    for i in range(20):
        # print(len(Dilithium2.sk_params[sk]))
        # msg = b"Your message signed by Dilithium" * 1000
        res = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
        msg = bytes(res.encode('UTF-8')) * 10
        start_time = time.time()
        sig, loop_i, y = Dilithium2.sign(sk, msg, precomputed=True)
        end_time = time.time()
        time_list.append(round(end_time - start_time, 4))
        loop_list.append(loop_i)
        
        # if y not in y_list:
        #     y_list.append(y)
        # else:
        #     print("Same Y")
        
        ver = Dilithium2.verify(pk, msg, sig)
        # print("verify result = {}".format(ver))
        # print("{}th test: Find the signature at {}th while loop with {} s (Total time).".format(i+1, loop_i, round(end_time - start_time, 4)))
        if ver != True:
            print("Signature Verify Failed")
    print("\n+++++++++++++++++++++++++++++++++")
    print("Summary:")
    print("Loops: {}".format(len(loop_list)))
    print(loop_list)
    print("Time: {}".format(len(time_list)))
    print(time_list)
    print("Average Loops: {}".format(sum(loop_list)/len(loop_list)))
    print("Average Time: {}".format(sum(time_list)/len(time_list)))
    avg_pre = sum(time_list)/len(time_list)
    
    print("Faster: {}".format(round(avg_normal - avg_pre, 5)))


# both_test()