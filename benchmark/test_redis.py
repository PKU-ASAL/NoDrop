#!/usr/bin/python3

import subprocess

LOOP = 10
REQUESTS_NUM = 30000
cmd = "redis-benchmark -n %d --csv"

def prepare():
    global cmd
    cmd = cmd % REQUESTS_NUM
    print(cmd)

def execute_redis_benmark():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    lines = f.stdout.decode("utf-8").split("\n")
    ret = float(lines[-2].split(",")[1][1:-1])
    return ret

res = []
prepare()
for i in range(LOOP):
    print("loop %d ..." % i, end="", flush=True)
    ret = execute_redis_benmark()
    res.append(ret)
    print(ret, "req/s")

total = sum(res)
avg = total / len(res)
variance = 0
for x in res:
    variance += (x - avg) * (x - avg)
variance /= len(res)
print("Variance:", variance)
print("Average:", round(1000000 * LOOP / total, 2), "us per req")