#!/usr/bin/python3

import os
import time
import subprocess
import signal
from multiprocessing import Process, Semaphore

#####################################
# Configuration
#####################################

# Redis server: single core
REDIS_CPU = os.environ.get("REDIS_CPU_CORE", "0")

# memtier: avoid Redis core
MEMTIER_CPU = os.environ.get("MEMTIER_CPU_CORES", "1-2")

LOOP = 10
DURATION = 10
THREADS = 4
CLIENTS = 64

UID = 1000

HOST = "127.0.0.1"
PORT = 6379

cmd = (
    f"taskset -c {MEMTIER_CPU} "
    f"./redis/memtier_/memtier_benchmark "
    f"--hide-histogram "
    f"-P redis "
    f"-s {HOST} -p {PORT} "
    f"-t {THREADS} -c {CLIENTS} "
    f"--test-time={DURATION} "
    f"--ratio=0:10"
)

#####################################
# Redis lifecycle
#####################################

def prepare():
    proc = subprocess.Popen(
        f"taskset -c {REDIS_CPU} "
        f"./redis/redis_/src/redis-server "
        f"./redis/redis_/redis.conf",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    return proc

def finish(proc):
    proc.send_signal(signal.SIGINT)
    time.sleep(1)

#####################################
# Benchmark execution
#####################################

def execute_redis_benchmark():
    try:
        f = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        lines = f.stdout.decode("utf-8").split("\n")
        for line in lines:
            if "Totals" in line:
                # Totals     Ops/sec    Hits/sec ...
                return float(line.split()[1])
        return 0
    except Exception as e:
        print("memtier error:", e)
        return 0

#####################################
# Multiprocessing logic
#####################################

s1 = Semaphore(0)
s2 = Semaphore(0)

def task1():
    first = True
    os.setgid(UID)
    os.setuid(UID)
    for _ in range(LOOP):
        s1.acquire()
        if not first:
            finish(proc)
        proc = prepare()
        first = False
        s2.release()
    s1.acquire()
    finish(proc)

def task2():
    res = []
    total_cost = 0

    print(cmd)

    for i in range(LOOP):
        print(f"loop {i} ...", end="", flush=True)
        s1.release()
        s2.acquire()

        start = time.time()
        ret = execute_redis_benchmark()
        total_cost += time.time() - start
        res.append(ret)

        print(round(ret, 2), "ops/sec")

    s1.release()

    avg = sum(res) / len(res)
    var = sum((x - avg) ** 2 for x in res) / len(res)

    print("Variance:", round(var, 6))
    print("Average:", round(avg, 2), "ops/sec")
    print("Total cost", round(total_cost, 3), "s")

#####################################
# Main
#####################################

def main():
    if os.getuid() != 0:
        print("Run as root")
        return

    p1 = Process(target=task1)
    p2 = Process(target=task2)

    p1.start()
    p2.start()

    p1.join()
    p2.join()

if __name__ == "__main__":
    main()
