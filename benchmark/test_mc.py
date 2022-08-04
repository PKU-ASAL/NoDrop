#!/usr/bin/python3

import os
import time
import subprocess
from multiprocessing import Process, Semaphore


LOOP = 10
# NRCPUS = 1;
NRCPUS = 16;
# NRCPUS = 32;
# METHOD = "set"
# CONNS = 1000
# NRCALLS = 1000
HOST = "localhost"
PORT = 11211
# THREAD = 1
THREAD = 8
# THREAD = 16
CLIENTS = 50
DURATION = 10

cmd = "./redis/memtier_/memtier_benchmark --hide-histogram -P memcache_binary -s %s -p %d " \
        "-t %d -c %d --test-time=%d" % (HOST, PORT, THREAD, CLIENTS, DURATION)
# cmd = "./memcached/mcperf_/src/mcperf --linger=0 --call-rate=1000 --conn-rate=1000 --sizes=d5120 --server=%s --port=%d "\
#         "--num-calls=%d --method=%s --num-conns=%d" % (HOST, PORT, NRCALLS, METHOD, CONNS)

def prepare():
    proc = subprocess.Popen("cgexec -g cpuset:app ./memcached/memcached_/memcached -d -t %d" % (NRCPUS), shell=True, stdout=subprocess.DEVNULL)
    time.sleep(3)
    return proc

def execute_postmark():
    f = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = f.stdout.decode("utf-8").split("\n")
    return float(lines[-2].strip().split()[-1].strip())
    # f = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE)
    # lines = f.stderr.decode("utf-8").split("\n")
    # for line in lines:
    #     if "Response rate:" in line:
    #         data = line.strip().split()[2].strip()
    #         return 1e6 / float(data)

    print("err")

def finish(proc):
    # proc.kill()
    subprocess.run("kill %d" % proc.pid, shell=True)
    time.sleep(3)

s1 = Semaphore(0)
s2 = Semaphore(0)

def task1():
    first = 1
    os.setgid(1000)
    os.setuid(1000)
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
    with open("/sys/fs/cgroup/cpuset/perf/tasks", "w") as f:
        f.write(str(os.getpid()))
    os.setgid(1000)
    os.setuid(1000)
    res = []
    total_cost = 0
    print(cmd)
    for i in range(LOOP):
        print("loop %d ..." % i, end="", flush=True)
        s1.release()
        s2.acquire()
        start = time.time()
        ret = execute_postmark()
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
    print("Average:", round(avg, 3), "us/req")
    print("Total cost", total_cost, "s")

def main():
    p1 = Process(target=task1)
    p2 = Process(target=task2)
    p1.start()
    p2.start()

main()
