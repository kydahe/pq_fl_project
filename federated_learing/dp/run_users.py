import sys
import os
import concurrent.futures
import subprocess


init_uid = 1
user_num = 2

# for i in range(0, user_num):
#     user_id = init_uid + i
#     cmd = "python3 user.py {}".format(user_id)
#     print(cmd)
#     os.system(cmd)

def run_script(user_id):
    cmd = f"python3 user.py {user_id}"
    subprocess.run(cmd, shell=True)

with concurrent.futures.ProcessPoolExecutor() as executor:
    user_ids = [init_uid + i for i in range(user_num)]
    executor.map(run_script, user_ids)
