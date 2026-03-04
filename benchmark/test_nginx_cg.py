#!/usr/bin/python3

import os
import time
import subprocess
from multiprocessing import Process, Semaphore

UID = 1000

# TOTAL_CPU, CPULINE = 1, 1     # C1
TOTAL_CPU, CPULINE = 5, 4     # C2
# TOTAL_CPU, CPULINE = 23, 16     # C3
# TOTAL_CPU, CPULINE = 39, 32   # C4
NRINSTANCE = 8

LOOP = 1
# NRCPUS = 2    #C1
NRCPUS = 8    #C2
# NRCPUS = 16     #C3
# NRCPUS = 32   #C4
CONNECTION = 100
DURATION = 20
URL = "http://127.0.0.1:8089/test.html"
cmd = "taskset -c %d-%d ./nginx/wrk_/wrk -t %d -c %d -d %d --timeout %d %s" % (CPULINE, TOTAL_CPU, NRCPUS, CONNECTION, DURATION, DURATION, URL)

def prepare():
    subprocess.run("taskset -c %d-%d ./nginx/nginx_/sbin/nginx" % (0, NRINSTANCE - 1), shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

def execute_wrk():
    try:
        f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        lines = f.stdout.decode("utf-8").split("\n")
        ret = float(lines[-3].split(": ")[-1])
        return 1e6 / ret
    except Exception as e:
        print("test_nginx_cg.py:", e)
        return 0


def finish():
    subprocess.run("./nginx/nginx_/sbin/nginx -s quit", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(1)
    subprocess.run("rm -rf ./nginx/nginx_/logs/access.log", shell=True)

s1 = Semaphore(0)
s2 = Semaphore(0)

def task1():
    first = 1
    os.setgid(UID)
    os.setuid(UID)
    for i in range(LOOP):
        s1.acquire()
        if first == 0:
            finish()
        prepare()
        first = 0
        s2.release()
    s1.acquire()
    finish()

def task2():
    # with open("/sys/fs/cgroup/cpuset/perf/tasks", "w") as f:
    #     f.write(str(os.getpid()))
    
    res = []
    total_cost = 0
    print(cmd)
    try:
        for i in range(LOOP):
            print("loop %d ..." % i, end="", flush=True)
            s1.release()
            s2.acquire()
            start = time.time()
            ret = execute_wrk()
            total_cost += time.time() - start
            res.append(ret)
            print(round(ret, 3), "us/req")

        s1.release()
        total = sum(res)
        avg = total / len(res)
        variance = 0
        for x in res:
            print(x)
            variance += (x - avg) * (x - avg)
        variance /= len(res)
        print("Variance:", round(variance, 6))
        print("Average:", round(avg, 2), "us per req")
        print("Total cost", total_cost, "s")

    except Exception as e:
        print(e)

def main():
    if os.getuid() != 0:
        print("Run as root")
        exit(0)
    p1 = Process(target=task1)
    p2 = Process(target=task2)
    p1.start()
    p2.start()

main()
