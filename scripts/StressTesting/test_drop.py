#!/bin/python3

import os, sys
import time
import signal
import subprocess

NRTHREAD = 4
CONFIG = [(100, 10), (100, 50), (100, 100), (100, 500), (100, 1000), (100, 5000), (100, 10000)]

def change(uid, gid):
    def result():
        os.setgid(gid)
        os.setuid(uid)
    return result

class Base:
    def start(self):
        pass

    def finish(self):
        self.n_evts = self.n_recv_evts = 0

    def stress(self, interval, loop, nr):
        proc = subprocess.Popen("cgexec -g cpuset:app /home/bench/stress %d %d %d" % (interval, loop, nr), 
                preexec_fn=change(1001, 1001), stdout=subprocess.PIPE, shell=True)
        proc.wait() 
        lines = proc.communicate()[0].decode("utf-8").split("\n");
        self.count = int(lines[0].strip().split("/")[0])

class Sysdig(Base):
    def start(self):
        self.proc = subprocess.Popen("exec cgexec -g cpuset:app /home/jeshrz/sysdig/build/userspace/sysdig/sysdig -w out.scap", shell=True)
        time.sleep(1)

    def finish(self):
        os.kill(self.proc.pid, signal.SIGINT)
        time.sleep(1)
        p = subprocess.run("dmesg -c", shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.decode("utf-8").split("\n")
        line = lines[-4]
        data = line.split()
        self.n_evts = int(data[-3])
        self.n_recv_evts = int(data[-1])
        self.n_recv_evts = self.n_evts - self.n_recv_evts

class NoDrop(Base):
    def finish(self):
        p = subprocess.run("/home/jeshrz/NoDrop/build/scripts/ctrl/ctrl stat", shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.decode("utf-8").split("\n")
        line = lines[-2]
        data = line.split()
        self.n_evts = int(data[0])
        subprocess.run("/home/jeshrz/NoDrop/build/scripts/ctrl/ctrl clear-stat", shell=True, stderr=subprocess.DEVNULL)

    def stress(self, interval, loop, nr):
        proc = subprocess.Popen("cgexec -g cpuset:app /home/bench/stress %d %d %d" % (interval, loop, nr), 
                preexec_fn=change(1001, 1001), stdout=subprocess.PIPE, shell=True)
        proc.wait() 
        lines = proc.communicate()[0].decode("utf-8").split("\n");
        self.count = 0
        self.n_recv_evts = 0
        for line in lines[:-1]:
            if "/" in line:
                self.count = int(line.split("/")[0])
            else:
                self.n_recv_evts += int(line)


def main(target):
    for cfg in CONFIG:
        target.start()
        target.stress(cfg[0], cfg[1], NRTHREAD)
        target.finish()
        print("%d/%d" % cfg, target.n_evts)
        print(target.count, target.n_recv_evts)

if __name__ == '__main__':
    if os.getuid() != 0:
        print("Run as root")
        exit(0)
    elif len(sys.argv) < 2:
        print("Usage: %s [sysdig|nodrop|lttng|kaudit]" % sys.argv[0])
        exit(0)

    if sys.argv[1] == "sysdig":
        target = Sysdig()
    elif sys.argv[1] == "nodrop":
        target = NoDrop()
    else:
        # TODO
        target = Base()

    main(target)
