#!/usr/bin/python3

import subprocess

LOOP = 10
cmd = "7z b -mmt1"

def prepare():
    print(cmd)

def execute_7z():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    lines = f.stdout.decode("utf-8").split("\n")
    ret = int(lines[-2].strip().split()[-1])
    return ret


res = []
prepare()
for i in range(LOOP):
    print("loop %d ...", end="", flush=True)
    ret = execute_7z()
    res.append(ret)
    print(ret, "MIPS")

total = sum(res)
avg = total / len(res)
variance = 0
for x in res:
    variance += (x - avg) * (x - avg)
variance /= len(res)
print("Variance:", variance)
print("Average:", round(total / LOOP), "MIPS")