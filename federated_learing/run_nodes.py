import concurrent.futures
import subprocess


init_nid = 101
node_num = 10

def run_script(node_id):
    cmd = f"python3 asnode.py {node_id}"
    subprocess.run(cmd, shell=True)

with concurrent.futures.ProcessPoolExecutor() as executor:
    node_ids = [init_nid + i for i in range(node_num)]
    executor.map(run_script, node_ids)
