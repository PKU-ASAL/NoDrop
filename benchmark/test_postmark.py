#!/usr/bin/python3

import time
import subprocess


LOOP = 10
NUMBER = 500
TRANSAC = 250000
MIN_SIZE = 5120
MAX_SIZE = 524288

config_file = "postmark.pmrc"
cmd = "postmark %s"

def prepare():
    global cmd
    with open(config_file, "w") as f:
        f.write("set transactions %d\n" % TRANSAC)
        # f.write("set size %d %d\n" % (MIN_SIZE, MAX_SIZE))
        f.write("set number %d\n" % NUMBER)
        # f.write("show\n")
        f.write("run\n")
        f.write("quit\n")

    cmd = cmd % config_file
    print(cmd)

def execute_postmark():
    start = time.time()
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    return (time.time() - start) * 1e3


res = []
total_cost = 0
prepare()
for i in range(LOOP):
    print("loop %d ..." % i, end="", flush=True)
    start = time.time()
    ret = execute_postmark()
    total_cost += time.time() - start
    res.append(ret)
    print(round(ret, 3), "ms")

total = sum(res)
avg = total / len(res)
variance = 0
for x in res:
    variance += (x - avg) * (x - avg)
variance /= len(res)
print("Variance:", round(variance, 6))
print("Average:", round(avg, 3), "ms")
print("Total cost", total_cost, "s")