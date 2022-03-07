#!/usr/bin/python3

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
        f.write("set size %d %d\n" % (MIN_SIZE, MAX_SIZE))
        f.write("set number %d\n" % NUMBER)
        f.write("show\n")
        f.write("run\n")
        f.write("quit\n")

    cmd = cmd % config_file
    print(cmd)

def execute_postmark():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    lines = f.stdout.decode("utf-8").split("\n")
    ret_line = 0
    for i, line in enumerate(lines):
        if line.startswith("Time:"):
            ret_line = i + 2
    ret = int(lines[ret_line].strip().split()[0])
    return ret


res = []
prepare()
for i in range(LOOP):
    print("loop %d ..." % i, end="", flush=True)
    ret = execute_postmark()
    res.append(ret)
    print(ret, "per second")

total = sum(res)
avg = total / len(res)
variance = 0
for x in res:
    variance += (x - avg) * (x - avg)
variance /= len(res)
print("Variance:", variance)
print("Average:", rond(total * 1000 / LOOP / TRANSAC, 2), "ms per req")