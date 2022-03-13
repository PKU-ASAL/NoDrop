#!/usr/bin/python3

import time
import subprocess

LOOP = 10
REQUESTS_NUM = 3000000
cmd = "./redis/redis_/src/redis-benchmark -n %d -P 32 -q -c 50 -t set,get,lpush,lpop,sadd --csv" % REQUESTS_NUM

def prepare():
    proc = subprocess.Popen("./redis/redis_/src/redis-server", shell=True, stdout=subprocess.DEVNULL)
    time.sleep(2)
    return proc

def execute_redis_benmark():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    lines = f.stdout.decode("utf-8").split("\n")
    for line in lines:
        data = line.split(",")
        if data[0] == '"LPUSH"':
            return 1e6 / float(data[1][1:-1])
    print("err")

def finish(proc):
    proc.terminate()

res = []
total_cost = 0
print(cmd)
try:
    for i in range(LOOP):
        print("loop %d ..." % i, end="", flush=True)
        proc = prepare()
        start = time.time()
        ret = execute_redis_benmark()
        total_cost += time.time() - start
        finish(proc)
        res.append(ret)
        print(round(ret, 3), "us/req")

    total = sum(res)
    avg = total / len(res)
    variance = 0
    for x in res:
        variance += (x - avg) * (x - avg)
    variance /= len(res)
    print("Variance:", round(variance, 6))
    print("Average:", round(avg, 3), "us per req")
    print("Total cost", total_cost, "s")

except Exception as e:
    print(e)