import os
user_nums = [200, 400, 600, 800, 1000]

def run_script(user_num):
    cmd = f"python3 all.py {user_num}"
    os.system(cmd)


for user_num in user_nums:
    run_script(user_num)
