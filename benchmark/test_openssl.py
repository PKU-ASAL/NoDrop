#!/usr/bin/python3

import os
import subprocess

LOOP = 10
TEST_SEC = 30
cmd = "openssl speed -multi %d -seconds %d rsa4096"

def prepare():
    global cmd
    nproc = os.cpu_count()
    cmd = cmd % (nproc, TEST_SEC)
    print(cmd)

def execute_openssl():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = f.stdout.decode("utf-8").split("\n")
    ret = float(lines[-2].split()[3][:-1])
    return ret

res = []
prepare()
for i in range(LOOP):
    print("loop %d ..." % i, end="", flush=True)
    ret = execute_openssl()
    res.append(ret)
    print(ret, "s per signature")

total = sum(res)
avg = total / len(res)
variance = 0
for x in res:
    variance += (x - avg) * (x - avg)
variance /= len(res)
print("Variance:", variance)
print("Average:", round(total * 1000000 / LOOP, 2), "us per signature")