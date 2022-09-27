#!/usr/bin/python3

import os
import time
import subprocess

UID = 1000

# TOTAL_CPU, CPULINE = 1, 1     #C1
TOTAL_CPU, CPULINE = 5, 4     #C2
# TOTAL_CPU, CPULINE = 23, 16     #C3
# TOTAL_CPU, CPULINE = 39, 32   #C4

LOOP = 1
TEST_SEC = 20
# cmd = "taskset -c %d-%d openssl speed -multi %d -seconds %d rsa4096"
cmd = "cgexec -g cpu:openssl cpuset:openssl openssl speed -multi %d -seconds %d rsa4096"

def prepare():
    global cmd
    # nproc = 1     #C1
    nproc = 4     #C2
    # nproc = 16      #C3
    # nproc = 32    #C4
    # cmd = cmd % (0, CPULINE - 1, nproc, TEST_SEC)
    cmd = cmd % (nproc, TEST_SEC)
    print(cmd)

def execute_openssl():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = f.stdout.decode("utf-8").split("\n")
    ret = float(lines[-2].split()[3][:-1])
    return ret * 1e6

if os.getuid() != UID:
    os.setgid(UID)
    os.setuid(UID)

res = []
total_cost = 0
prepare()
for i in range(LOOP):
    print("loop %d ..." % i, end="", flush=True)
    start = time.time()
    ret = execute_openssl()
    total_cost += time.time() - start
    res.append(ret)
    print(round(ret, 3), "us/signature")

total = sum(res)
avg = total / len(res)
variance = 0
for x in res:
    print(x)
    variance += (x - avg) * (x - avg)
variance /= len(res)
print("Variance:", round(variance, 6))
print("Average:", round(avg, 3), "us per signature")
print("Total cost", total_cost, "s")
