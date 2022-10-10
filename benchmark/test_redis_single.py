#!/usr/bin/python3

import os
import time
import subprocess
import signal
from multiprocessing import Process, Semaphore

UID = 1000

REDIS_NR, BENCH_BEGIN, BENCH_END = 1, 1, 2      #C1: redis 1 0, benchmark 1 1~2
# REDIS_NR, BENCH_BEGIN, BENCH_END = 4, 4, 9      #C2: redis 4 0~3 benchmark 4 4~9
# REDIS_NR, BENCH_BEGIN, BENCH_END = 8, 16, 23    #C3: redis 8 0~7 benchmark 8 16~23
# REDIS_NR, BENCH_BEGIN, BENCH_END = 12, 22, 39   #C4: redis 12 0~11 benchmark 12 22~39

LOOP = 10
THREAD = 2
CLIENTS = 200
REQS = 1000000

HOST = "localhost"
PORT = 6379

def prepare():
    procs = []
    for idx in range(REDIS_NR):
        f = subprocess.Popen("exec taskset -c %d ./redis/redis_/src/redis-server ./redis/redis_/redis_%d.conf" % (idx, PORT + idx), shell=True, stdout=subprocess.DEVNULL)
        procs.append(f)
    time.sleep(1)
    return procs

def execute_redis_benmark():
    procs = []
    for i in range(REDIS_NR):
        cmd = "taskset -c %d ./redis/redis_/src/redis-benchmark -h %s -p %d -q -t get --csv -d 0 "\
                " -c %d -n %d" % (BENCH_BEGIN + i, HOST, PORT + i, CLIENTS, REQS)
        f = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        procs.append(f)

    total = 0
    for f in procs:
        out = f.communicate()[0]
        lines = out.decode("utf-8").split("\n")
        data = lines[0].split(",")[1]
        total += float(data[1:-1])
    return total

def finish(procs):
    for f in procs:
        os.kill(f.pid, signal.SIGINT)
    time.sleep(1)

s1 = Semaphore(0)
s2 = Semaphore(0)

def task1():
    first = 1
    os.setgid(UID)
    os.setuid(UID)
    for i in range(LOOP):
        s1.acquire()
        if first == 0:
            finish(proc)
        proc = prepare()
        first = 0
        s2.release()
    s1.acquire()
    finish(proc)

def task2():
    res = []
    total_cost = 0
    try:
        for i in range(LOOP):
            print("loop %d ..." % i, end="", flush=True)
            s1.release()
            s2.acquire()
            start = time.time()
            ret = execute_redis_benmark()
            total_cost += time.time() - start
            res.append(ret)
            print(round(ret, 3), "reqs/s")

        s1.release()
        total = sum(res)
        avg = total / len(res)
        variance = 0
        for x in res:
            print(x)
            variance += (x - avg) * (x - avg)
        variance /= len(res)
        print("Variance:", round(variance, 6))
        print("Average:", round(avg, 3), "reqs/s")
        print("Total cost", total_cost, "s")

    except Exception as e:
        print(e)

def main():
    p1 = Process(target=task1)
    p2 = Process(target=task2)
    p1.start()
    p2.start()

main()
