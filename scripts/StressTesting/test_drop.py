#!/bin/python3

import os, sys
import time
import signal
import subprocess

NRTHREAD = 1
# CONFIG = [(100, 10), (100, 50), (100, 100), (100, 500), (100, 1000), (100, 5000), (100, 10000)]
CONFIG = [(100, 10), (100, 10)]

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
        proc = subprocess.Popen("/home/bench/stress %d %d %d" % (interval, loop, nr), 
                preexec_fn=change(1001, 1001), stdout=subprocess.PIPE, shell=True)
        proc.wait() 
        lines = proc.communicate()[0].decode("utf-8").split("\n");
        self.count = int(lines[0].strip().split("/")[0])

class Sysdig(Base):
    def start(self):
        self.proc = subprocess.Popen("exec /home/jeshrz/sysdig/build/userspace/sysdig/sysdig -w out.scap", shell=True)
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
        proc = subprocess.Popen("/home/bench/stress %d %d %d" % (interval, loop, nr), 
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

class Lttng(Base):
    PREFIX = "/home/jeshrz/lttng/install/bin/"
    SESSION_PATH = "/tmp/test-session"

    def start(self):
        subprocess.run(Lttng.PREFIX + "lttng create test-session --output=" + Lttng.SESSION_PATH, shell=True, stdout=subprocess.DEVNULL)
        subprocess.run(Lttng.PREFIX + "lttng enable-event --kernel --syscall --all", shell=True, stdout=subprocess.DEVNULL)
        subprocess.run(Lttng.PREFIX + "lttng track --kernel --vuid=bench", shell=True, stdout=subprocess.DEVNULL)
        subprocess.run(Lttng.PREFIX + "lttng start", shell=True, stdout=subprocess.DEVNULL)

    def finish(self):
        subprocess.run(Lttng.PREFIX + "lttng stop", shell=True, stdout=subprocess.DEVNULL)

        p = subprocess.run(Lttng.PREFIX + "lttng status", shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.decode("utf-8").split("\n")
        n_drop_evts = 0
        for line in lines:
            if "Discarded events" in line:
                n_drop_evts = int(line.strip().split()[-1])
                break
        subprocess.run(Lttng.PREFIX + "lttng destroy", shell=True, stdout=subprocess.PIPE)

        self.get_n_evts()
        self.n_evts = n_drop_evts + self.n_recv_evts
    
    def get_n_evts(self):
        import bt2

        # Create a trace collection message iterator with this path.
        msg_it = bt2.TraceCollectionMessageIterator(Lttng.SESSION_PATH)
        self.n_recv_evts = 0

        # Iterate the trace messages.
        for msg in msg_it:
            # `bt2._EventMessageConst` is the Python type of an event message.
            if type(msg) is bt2._EventMessageConst:
                self.n_recv_evts += 1

class Kaudit(Base):
    def start(self):
        subprocess.run("rm -rf /var/log/audit/audit.log", shell=True)
        subprocess.run("service auditd restart", shell=True, stdout=subprocess.DEVNULL)
        subprocess.run("auditctl -a always,exit -S all -F uid=bench", shell=True)

    def finish(self):
        subprocess.run("auditctl -D", shell=True, stdout=subprocess.DEVNULL)

        n_drop_evts = 0

        p = subprocess.run("auditctl -s", shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.decode("utf-8").split("\n")
        for line in lines:
            if "lost" in line:
                n_drop_evts = int(line.split()[1])
                break

        n_recv_evts = 0
        p = subprocess.run("aureport --summary", shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.decode("utf-8").split("\n")
        for line in lines:
            if "Number of events" in line:
                n_recv_evts = int(line.split(":")[1].strip())
                break

        self.n_evts = n_drop_evts + n_recv_evts
        self.n_recv_evts = n_recv_evts


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
    elif sys.argv[1] == "lttng":
        target = Lttng()
    elif sys.argv[1] == "kaudit":
        target = Kaudit()
    else:
        # TODO
        target = Base()

    main(target)
