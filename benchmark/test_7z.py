#!/usr/bin/python3

import time
import subprocess

LOOP = 10
cmd = "7z b"

def prepare():
    print(cmd)

def execute_7z():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    lines = f.stdout.decode("utf-8").split("\n")
    ret = int(lines[-2].strip().split()[-1])
    return ret


res = []
total_cost = 0
prepare()
for i in range(LOOP):
    print("loop %d ..." % i, end="", flush=True)
    start = time.time()
    ret = execute_7z()
    total_cost += time.time() - start
    res.append(ret)
    print(ret, "MIPS")

total = sum(res)
avg = total / len(res)
variance = 0
for x in res:
    variance += (x - avg) * (x - avg)
variance /= len(res)
print("Variance:", round(variance, 6))
print("Average:", round(avg), "MIPS")
print("Total cost", total_cost, "s")