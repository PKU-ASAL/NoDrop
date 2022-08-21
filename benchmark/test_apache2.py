#!/usr/bin/python3

import os
import time
import subprocess


LOOP = 10
CONNECTION = 10000
DURATION = 30
NRCPUS = os.cpu_count()
URL = "http://127.0.0.1:8088/test.html"
cmd = "./nginx/wrk_/wrk -t %d -c %d -d %d --timeout %d %s" % (NRCPUS, CONNECTION, DURATION, DURATION, URL)

def prepare():
    subprocess.run("./apache2/httpd_/bin/apachectl -k start -f conf/httpd.conf", shell=True)
    time.sleep(1)


def execute_wrk():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = f.stdout.decode("utf-8").split("\n")
    ret = float(lines[-3].split(": ")[-1])
    return 1e6/ret

def finish():
    subprocess.run("./apache2/httpd_/bin/apachectl -k stop", shell=True)
    time.sleep(1)
    # subprocess.run("rm -f apache2/httpd_/logs/*", shell=True)

res = []
print(cmd)
try:
    for i in range(LOOP):
        prepare()
        print("loop %d ..." % i, end="", flush=True)
        ret = execute_wrk()
        res.append(ret)
        print(ret, "us/req")
        finish()

    total = sum(res)
    avg = total / len(res)
    variance = 0
    for x in res:
        variance += (x - avg) * (x - avg)
    variance /= len(res)
    print("Variance:", round(variance, 6))
    print("Average:", round(avg, 2), "us/req")

    for x in res:
        print(round(x, 3))

except Exception as e:
    print(e)
