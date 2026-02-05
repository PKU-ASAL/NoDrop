#!/usr/bin/python3

import os
import time
import shutil
import subprocess

#####################################
# Configuration
#####################################

# C1: postmark uses exactly 1 core
POSTMARK_CPU = os.environ.get("TARGET_CPU_CORE", "0")

LOOP = 10

# Postmark parameters
NUMBER = 500
TRANSAC = 10000
MIN_SIZE = 5120
MAX_SIZE = 524288

WORKDIR = "./postmark_data"
CONFIG_FILE = "postmark.pmrc"

#####################################
# Prepare config and workdir
#####################################

def prepare():
    # Clean working directory (very important)
    if os.path.exists(WORKDIR):
        shutil.rmtree(WORKDIR)
    os.makedirs(WORKDIR, exist_ok=True)

    with open(CONFIG_FILE, "w") as f:
        f.write(f"set transactions {TRANSAC}\n")
        f.write(f"set size {MIN_SIZE} {MAX_SIZE}\n")
        f.write(f"set number {NUMBER}\n")
        f.write(f"set location {WORKDIR}\n")
        f.write("show\n")
        f.write("run\n")
        f.write("quit\n")

#####################################
# Execute postmark
#####################################

def execute_postmark():
    cmd = f"taskset -c {POSTMARK_CPU} postmark {CONFIG_FILE}"
    start = time.time()
    subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return (time.time() - start) * 1e3   # ms

#####################################
# Main benchmark loop
#####################################

def main():
    if os.getuid() != 0:
        print("Run as root")
        return

    prepare()

    res = []
    total_cost = 0

    for i in range(LOOP):
        print(f"loop {i} ...", end="", flush=True)
        start = time.time()
        ret = execute_postmark()
        total_cost += time.time() - start
        res.append(ret)
        print(round(ret, 3), "ms")

    avg = sum(res) / len(res)
    var = sum((x - avg) ** 2 for x in res) / len(res)

    print("Variance:", round(var, 6))
    print("Average:", round(avg, 3), "ms")
    print("Total cost", round(total_cost, 3), "s")

if __name__ == "__main__":
    main()
