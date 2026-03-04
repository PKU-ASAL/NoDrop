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

# memtier: avoid Redis core (can be 1-7 etc.)
MEMTIER_CPU = os.environ.get("MEMTIER_CPU_CORES", "1-7")

LOOP = 10
DURATION = 10
THREADS = 2
CLIENTS = 64

HOST = "127.0.0.1"
PORT = 6379

# cgroup v1 memory limit (provided by run_bench.sh)
REDIS_MEM_CGROUP_NAME = os.environ.get("REDIS_MEM_CGROUP_NAME", "redis_bench")
REDIS_MEM_LIMIT_BYTES = int(os.environ.get("REDIS_MEM_LIMIT_BYTES", str(2 * 1024 * 1024 * 1024)))
CGROUP_MEM_BASE = "/sys/fs/cgroup/memory"
CGROUP_PATH = os.path.join(CGROUP_MEM_BASE, REDIS_MEM_CGROUP_NAME)

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
# Helpers: cgroup v1 memory
#####################################

def ensure_mem_cgroup():
    """
    Best-effort ensure the memory cgroup exists and has the expected limit.
    run_bench.sh already does this; we keep a lightweight safety net here.
    """
    if not os.path.isdir(CGROUP_MEM_BASE):
        print(f"[WARN] {CGROUP_MEM_BASE} not found; skip memory limit.")
        return False

    try:
        os.makedirs(CGROUP_PATH, exist_ok=True)
        limit_path = os.path.join(CGROUP_PATH, "memory.limit_in_bytes")
        with open(limit_path, "w") as f:
            f.write(str(REDIS_MEM_LIMIT_BYTES))
        return True
    except Exception as e:
        print("[WARN] ensure_mem_cgroup failed:", e)
        return False

def attach_pid_to_mem_cgroup(pid: int):
    """
    Attach Redis pid into /sys/fs/cgroup/memory/<group>/tasks
    """
    try:
        tasks_path = os.path.join(CGROUP_PATH, "tasks")
        with open(tasks_path, "w") as f:
            f.write(str(pid))
    except Exception as e:
        print("[WARN] attach pid to mem cgroup failed:", e)

#####################################
# Redis lifecycle
#####################################

def prepare():
    # best-effort: make sure port 6379 not occupied by stale process
    subprocess.run("pids=$(lsof -t -iTCP:6379 -sTCP:LISTEN 2>/dev/null || true); "
                   "if [ -n \"$pids\" ]; then kill -9 $pids || true; fi",
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    proc = subprocess.Popen(
        f"taskset -c {REDIS_CPU} "
        f"./redis/redis_/src/redis-server "
        f"./redis/redis_/redis.conf",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # attach to cgroup ASAP
    if ensure_mem_cgroup():
        # tiny sleep so /proc/<pid> exists and tasks write is accepted
        time.sleep(0.2)
        attach_pid_to_mem_cgroup(proc.pid)

    # wait for redis to listen
    time.sleep(1.0)
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
        lines = f.stdout.decode("utf-8", errors="ignore").split("\n")
        for line in lines:
            if line.strip().startswith("Totals"):
                # Totals     Ops/sec    Hits/sec ...
                return float(line.split()[1])
        return 0.0
    except Exception as e:
        print("memtier error:", e)
        return 0.0

#####################################
# Multiprocessing logic
#####################################

s1 = Semaphore(0)
s2 = Semaphore(0)

def task1():
    proc = None
    first = True
    for _ in range(LOOP):
        s1.acquire()
        if not first and proc is not None:
            finish(proc)
        proc = prepare()
        first = False
        s2.release()
    s1.acquire()
    if proc is not None:
        finish(proc)

def task2():
    res = []
    total_cost = 0.0

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

    avg = sum(res) / len(res) if res else 0.0
    var = sum((x - avg) ** 2 for x in res) / len(res) if res else 0.0

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