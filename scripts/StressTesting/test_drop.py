#!/bin/python3

import bt2
import os, sys
import time
import signal
import subprocess

UID = 1001
USER = "bench"

NRTHREAD = 1
CONFIG = [(10, 10000), (50, 10000), (100, 10000), (500, 10000), (1000, 10000), (5000, 10000), (10000, 10000)]
# CONFIG = [(10000, 10000)]

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

    def stress(self, n, m, nr):
        subprocess.run("rm -rf /tmp/count/*", shell=True)

        for i in range(nr):
            subprocess.Popen("taskset -c %d timeout -s SIGINT 30s /home/%s/stress %d %d %d" % (i, USER, n, m, i),
                    preexec_fn=change(UID, UID), shell=True)

        time.sleep(31)
        self.count = 0
        for path, _, filelist in os.walk("/tmp/count"):
            for filename in filelist:
                with open(os.path.join(path, filename), "r") as f:
                    line = f.readline()
                    self.count += int(line.strip().split("/")[0])

class Sysdig(Base):
    def start(self):
        self.proc = subprocess.Popen("exec /home/jeshrz/sysdig/build/userspace/sysdig/sysdig -w /tmp/out.scap", shell=True)
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
    def start(self):
        subprocess.run("rm -rf /tmp/nodrop/*.buf", shell=True)

    def finish(self):
        p = subprocess.run("/home/jeshrz/NoDrop/build/scripts/ctrl/ctrl stat", shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.decode("utf-8").split("\n")
        line = lines[-2]
        data = line.split()
        self.n_evts = int(data[0])
        subprocess.run("/home/jeshrz/NoDrop/build/scripts/ctrl/ctrl clear-stat", shell=True, stderr=subprocess.DEVNULL)

        self.n_recv_evts = 0
        for path, _, filelist in os.walk("/tmp/nodrop/count"):
            for filename in filelist:
                with open(os.path.join(path, filename), "r") as f:
                    fileline = f.readline()
                    if fileline:
                        self.n_recv_evts += int(fileline)

class Lttng(Base):
    PREFIX = "/home/jeshrz/lttng/install/bin/"
    SESSION_PATH = "/tmp/test-session"
    CHANNEL_NAME = "channel0"
    READ_TIMER = 2000

    def start(self):
        subprocess.run(Lttng.PREFIX + "lttng create test-session --output=%s" % Lttng.SESSION_PATH, shell=True, stdout=subprocess.DEVNULL)
        subprocess.run(Lttng.PREFIX + "lttng enable-channel --kernel %s --read-timer=%d" % (Lttng.CHANNEL_NAME, Lttng.READ_TIMER), shell=True, stdout=subprocess.DEVNULL)
        subprocess.run(Lttng.PREFIX + "lttng enable-event --kernel --syscall --all -c %s" % Lttng.CHANNEL_NAME, shell=True, stdout=subprocess.DEVNULL)
        subprocess.run(Lttng.PREFIX + "lttng track --kernel --vuid=%d" % UID, shell=True, stdout=subprocess.DEVNULL)
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
        self.n_recv_evts = 0

        # Create a trace collection message iterator with this path.
        msg_it = bt2.TraceCollectionMessageIterator(Lttng.SESSION_PATH)
        # Iterate the trace messages.
        for msg in msg_it:
            # `bt2._EventMessageConst` is the Python type of an event message.
            if type(msg) is bt2._EventMessageConst:
                self.n_recv_evts += 1

class Kaudit(Base):
    def start(self):
        subprocess.run("rm -rf /tmp/audit/*", shell=True)
        subprocess.run("service auditd restart", shell=True, stdout=subprocess.DEVNULL)
        subprocess.run("auditctl -a always,exit -S all -F uid=%d" % UID, shell=True)

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
    elif len(sys.argv) < 3:
        print("Usage: %s [sysdig|nodrop|lttng|audit] <nrcore>" % sys.argv[0])
        exit(0)

    NRTHREAD = int(sys.argv[2])

    subprocess.run("mkdir -p /tmp/count", shell=True)
    subprocess.run("chgrp -R %d /tmp/count" % UID, shell=True)
    subprocess.run("chown -R %d /tmp/count" % UID, shell=True)

    if sys.argv[1] == "sysdig":
        target = Sysdig()
    elif sys.argv[1] == "nodrop":
        target = NoDrop()
    elif sys.argv[1] == "lttng":
        target = Lttng()
    elif sys.argv[1] == "audit":
        target = Kaudit()
    else:
        target = Base()

    main(target)
