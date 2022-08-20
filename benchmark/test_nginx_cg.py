#!/usr/bin/python3

import os
import time
import subprocess
from multiprocessing import Process, Semaphore

TOTAL_CPU = 1
CPULINE = 1

LOOP = 10
NRCPUS = 2
# NRCPUS = 16
CONNECTION = 100
DURATION = 10
URL = "http://127.0.0.1:8089/test.html"
cmd = "taskset -c %d-%d /home/jeshrz/wrk/wrk -t %d -c %d -d %d --timeout %d %s" % (CPULINE, TOTAL_CPU, NRCPUS, CONNECTION, DURATION, DURATION, URL)

def prepare():
    subprocess.run("taskset -c %d-%d ./nginx/nginx_/sbin/nginx" % (0, CPULINE - 1), shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

def execute_wrk():
    try:
        f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        lines = f.stdout.decode("utf-8").split("\n")
        ret = float(lines[-3].split(": ")[-1])
        return 1e6 / ret
    except Exception:
        return 0


def finish():
    subprocess.run("./nginx/nginx_/sbin/nginx -s quit", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(1)
    subprocess.run("rm -rf ./nginx/nginx_/logs/access.log", shell=True)

s1 = Semaphore(0)
s2 = Semaphore(0)

def task1():
    first = 1
    os.setgid(1000)
    os.setuid(1000)
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
