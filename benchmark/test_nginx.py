#!/usr/bin/python3

import os
import subprocess


LOOP = 10
CONNECTION = 1000
NRCPUS = os.cpu_count()
URL = "http://127.0.0.1:8089/test.html"
cmd = "wrk -t %d -c %d %s"

def prepare():
    global cmd
    subprocess.run("./nginx/nginx_/sbin/nginx", shell=True)
    cmd = cmd % (NRCPUS // 2, CONNECTION, URL)
    print(cmd)

def execute_wrk():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = f.stdout.decode("utf-8").split("\n")
    ret = float(lines[-3].split(": ")[-1])
    return ret

def finish():
    subprocess.run("./nginx/nginx_/sbin/nginx -s quit", shell=True)
    subprocess.run("rm -f nginx/nginx_/logs/*", shell=True)

res = []
prepare()
for i in range(LOOP):
    print("loop %d ..." % i, end="", flush=True)
    ret = execute_wrk()
    res.append(ret)
    print(ret, "req/s")

total = sum(res)
avg = total / len(res)
variance = 0
for x in res:
    variance += (x - avg) * (x - avg)
variance /= len(res)
print("Variance:", variance)
print("Average:", round(LOOP * 1000000 / total, 2), "us per req")

finish()