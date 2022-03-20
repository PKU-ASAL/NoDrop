#!/usr/bin/python3

import os
import time
import subprocess


LOOP = 10
CONNECTION = 1000
NRCPUS = os.cpu_count()
URL = "http://127.0.0.1:8089/test.html"
cmd = "wrk -t %d -c %d %s" % (NRCPUS, CONNECTION, URL)

def prepare():
    subprocess.run("./nginx/nginx_/sbin/nginx", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def execute_wrk():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = f.stdout.decode("utf-8").split("\n")
    ret = float(lines[-3].split(": ")[-1])
    return 1e6 / ret

def finish():
    subprocess.run("./nginx/nginx_/sbin/nginx -s quit", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

res = []
total_cost = 0
print(cmd)
try:
    for i in range(LOOP):
        print("loop %d ..." % i, end="", flush=True)
        prepare()
        start = time.time()
        ret = execute_wrk()
        total_cost += time.time() - start
        finish()
        res.append(ret)
        print(round(ret, 3), "us/req")

    total = sum(res)
    avg = total / len(res)
    variance = 0
    for x in res:
        variance += (x - avg) * (x - avg)
    variance /= len(res)
    print("Variance:", round(variance, 6))
    print("Average:", round(avg, 2), "us per req")
    print("Total cost", total_cost, "s")

except Exception as e:
    print(e)