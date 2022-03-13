#!/usr/bin/python3

import os
import subprocess


LOOP = 10
CONNECTION = 1000
NRCPUS = os.cpu_count()
URL = "http://127.0.0.1:8088/test.html"
cmd = "../../wrk/wrk -t %d -c %d %s" % (NRCPUS, CONNECTION, URL)

def prepare():
    subprocess.run("./apache2/httpd_/bin/apachectl -k start -f conf/httpd.conf", shell=True)


def execute_wrk():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = f.stdout.decode("utf-8").split("\n")
    print(lines)
    ret = float(lines[-3].split(": ")[-1])
    return 1e6/ret

def finish():
    subprocess.run("./apache2/httpd_/bin/apachectl -k stop", shell=True)
    subprocess.run("rm -f apache2/httpd_/logs/*", shell=True)

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
except Exception as e:
    print(e)
finally:
    finish()