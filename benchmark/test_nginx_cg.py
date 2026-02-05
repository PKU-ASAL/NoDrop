#!/usr/bin/python3

import os
import time
import subprocess
from multiprocessing import Process, Semaphore

#####################################
# Configuration
#####################################

# nginx uses exactly 1 core
NGINX_CPU = os.environ.get("NGINX_CPU_CORE", "0")

# wrk runs on other cores
WRK_CPU = os.environ.get("WRK_CPU_CORES", "1-2")

NRINSTANCE = 1       # nginx worker instances (not CPU cores)

LOOP = 1
NRCPUS = 8           # wrk threads
CONNECTION = 100
DURATION = 20
URL = "http://127.0.0.1:8089/test.html"

UID = 1000

cmd = (
    f"taskset -c {WRK_CPU} ./nginx/wrk_/wrk "
    f"-t {NRCPUS} -c {CONNECTION} -d {DURATION} "
    f"--timeout {DURATION} {URL}"
)

#####################################
# nginx lifecycle
#####################################

def prepare():
    subprocess.run(
        f"taskset -c {NGINX_CPU} ./nginx/nginx_/sbin/nginx",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

def finish():
    subprocess.run(
        "./nginx/nginx_/sbin/nginx -s quit",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    subprocess.run(
        "rm -rf ./nginx/nginx_/logs/access.log",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

#####################################
# wrk execution
#####################################

def execute_wrk():
    try:
        f = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        lines = f.stdout.decode("utf-8").split("\n")
        # wrk output: latency average is usually third line from bottom
        ret = float(lines[-3].split(": ")[-1])
        return 1e6 / ret   # us per request
    except Exception as e:
        print("execute_wrk error:", e)
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
            finish()
        prepare()
        first = False
        s2.release()
    s1.acquire()
    finish()

def task2():
    res = []
    total_cost = 0

    print(cmd)

    for i in range(LOOP):
        print(f"loop {i} ...", end="", flush=True)
        s1.release()
        s2.acquire()

        start = time.time()
        ret = execute_wrk()
        total_cost += time.time() - start

        res.append(ret)
        print(round(ret, 3), "us/req")

    s1.release()

    avg = sum(res) / len(res)
    var = sum((x - avg) ** 2 for x in res) / len(res)

    print("Variance:", round(var, 6))
    print("Average:", round(avg, 2), "us per req")
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
