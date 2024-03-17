import sys
import os
import concurrent.futures
import subprocess
# from user import *


init_uid = 1
user_num = 200

# for i in range(0, user_num):
#     user_id = init_uid + i
#     cmd = "python3 user.py {}".format(user_id)
#     print(cmd)
#     os.system(cmd)

# vectors = []
# users = []

def run_script(user_id):
    cmd = f"python3 user.py {user_id}"
    subprocess.run(cmd, shell=True)

# def run_preparing(user_id):
#     # user_id = sys.argv[1]
#     node = UserClient(user_id)
#     node.preparing()
#     w = node.generate_vector()
#     vectors.append(w)
#     users.append(node)

# def run_one_client(user, vector):
#     run_one_user(user, vector)

# user_ids = [init_uid + i for i in range(user_num)]

# for i in range(user_num):
#     user_id = init_uid + i
#     run_preparing(user_id)
# max_workers = user_num
with concurrent.futures.ProcessPoolExecutor() as executor:
    user_ids = [init_uid + i for i in range(user_num)]
    executor.map(run_script, user_ids)
    # executor.map(run_one_client, users, vectors)
