#!/usr/bin/python3

import os
import time
import subprocess
import signal
from multiprocessing import Process, Semaphore

UID = 1000

# TOTAL_CPU, CPULINE = 1, 1     #C1
# TOTAL_CPU, CPULINE = 5, 4     #C2
TOTAL_CPU, CPULINE = 23, 16     #C3
# TOTAL_CPU, CPULINE = 39, 32   #C4

LOOP = 1
# THREAD = 2    #C1
# THREAD = 4    #C2
THREAD = 8      #C3
# THREAD = 16   #C4
DURATION = 10
CLIENTS = 50
HOST = "localhost"
PORT = 6379
cmd = "taskset -c %d-%d ./redis/memtier_/memtier_benchmark --hide-histogram -P redis -s %s -p %d " \
        "-t %d -c %d --test-time=%d" % (CPULINE, TOTAL_CPU, HOST, PORT, THREAD, CLIENTS, DURATION)
# cmd = "./redis/redis_/src/redis-benchmark -h %s -p %d -n %d -P 32 -q -c 50 -t set,get,lpush,lpop,sadd --csv" % (HOST, PORT, REQUESTS_NUM)

def prepare():
    proc = subprocess.Popen("exec taskset -c %d-%d ./redis/redis_/src/redis-server ./redis/redis_/redis.conf" % (0, CPULINE - 1), shell=True, stdout=subprocess.DEVNULL)
    time.sleep(1)
    return proc

def execute_redis_benmark():
    try:
        f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        lines = f.stdout.decode("utf-8").split("\n")
        return float(lines[-2].strip().split(" ")[-1].strip())
    except Exception:
        return 0
    # for line in lines:
    #     data = line.split(",")
    #     if data[0] == '"LPUSH"':
    #         return 1e6 / float(data[1][1:-1])

def finish(proc):
    os.kill(proc.pid, signal.SIGINT)
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
            ret = execute_redis_benmark()
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
        print("Average:", round(avg, 3), "us per req")
        print("Total cost", total_cost, "s")

    except Exception as e:
        print(e)

def main():
    p1 = Process(target=task1)
    p2 = Process(target=task2)
    p1.start()
    p2.start()

main()
