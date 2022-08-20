#!/usr/bin/python3

import os
import time
import subprocess

LOOP = 10
TEST_SEC = 10
cmd = "cgexec -g cpuset:app openssl speed -multi %d -seconds %d rsa4096"

def prepare():
    global cmd
    # nproc = 1
    nproc = 32
    cmd = cmd % (nproc, TEST_SEC)
    print(cmd)

def execute_openssl():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = f.stdout.decode("utf-8").split("\n")
    ret = float(lines[-2].split()[3][:-1])
    return ret * 1e6

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
