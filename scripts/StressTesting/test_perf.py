#!/bin/python3

import os, sys
import time
import signal
import subprocess

UID = 1000
USER = "jeshrz"

# CONFIG = [(10, 10000), (50, 10000), (100, 10000), (500, 10000), (1000, 10000), (5000, 10000), (10000, 10000)]
CONFIG = [(0, 10000), (10, 10000), (20, 10000), (30, 10000), (40, 10000), (50, 10000), (100, 10000)]
# CONFIG = [(10000, 0)]

def change(uid, gid):
    def result():
        os.setgid(gid)
        os.setuid(uid)
    return result


class Nginx:
    def run(self, toolname, nr, n, m, iter):
        f = subprocess.run("./test_nginx_cg.py", shell=True, stdout=subprocess.PIPE)
        # f = subprocess.run("./test_nginx_cg.py", shell=True)
        lines = f.stdout.decode("utf-8").split("\n")
        with open("%s-%s-%d-%d-%d.out.%d" % (toolname, type(self).__name__, nr, n, m, iter), "w") as f:
            for line in lines:
                f.write(line)
                f.write("\n")
        line = lines[-3]
        ret = float(line.strip().split()[1])
        return ret

class Redis:
    def run(self, toolname, nr, n, m, iter):
        f = subprocess.run("./test_redis.py", shell=True, stdout=subprocess.PIPE)
        lines = f.stdout.decode("utf-8").split("\n")
        with open("%s-%s-%d-%d-%d.out.%d" % (toolname, type(self).__name__, nr, n, m, iter), "w") as f:
            for line in lines:
                f.write(line)
                f.write("\n")
        line = lines[-3]
        ret = float(line.strip().split()[1])
        return ret

class Openssl:
    def run(self, toolname, nr, n, m, iter):
        f = subprocess.run("./test_openssl.py", shell=True, stdout=subprocess.PIPE)
        lines = f.stdout.decode("utf-8").split("\n")
        with open("%s-%s-%d-%d-%d.out.%d" % (toolname, type(self).__name__, nr, n, m, iter), "w") as f:
            for line in lines:
                f.write(line)
                f.write("\n")
        line = lines[-3]
        ret = float(line.strip().split()[1])
        return ret


class Base:
    def __init__(self, nr):
        self.nr = nr

    def start(self):
        self.proc = subprocess.Popen("exec taskset -c %d-%d /home/jeshrz/sysdig/build/userspace/sysdig/sysdig -w /tmp/out-vanilla.scap" % (0, self.nr - 1), shell=True)
        time.sleep(2)
        os.kill(self.proc.pid, signal.SIGSTOP)
        time.sleep(2)
        pass

    def finish(self):
        os.kill(self.proc.pid, signal.SIGCONT)
        time.sleep(2)
        os.kill(self.proc.pid, signal.SIGINT)
        time.sleep(2)
        subprocess.run("rm -rf /tmp/out-vanilla.scap", shell=True)
        p = subprocess.run("dmesg -c", shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.decode("utf-8").split("\n")
        line = lines[-4]
        data = line.split()
        self.n_evts = int(data[-3])
        self.n_recv_evts = int(data[-1])
        self.n_recv_evts = self.n_evts - self.n_recv_evts
        # self.n_evts = self.n_recv_evts = 0

    def stress(self, n, m, app, nr, iter):
        subprocess.run("rm -rf /tmp/count/*", shell=True)

        procs = []
        # for i in range(8):
        #     f = subprocess.Popen("exec taskset -c %d /home/%s/stress %d %d %d" % (i, USER, n, m, i),
        #             preexec_fn=change(UID, UID), shell=True)
        #     procs.append(f)
        #
        # for i in range(8, nr):
        #     f = subprocess.Popen("exec taskset -c %d /home/%s/stress %d %d %d" % (i, USER, n, m, i),
        #             preexec_fn=change(UID, UID), shell=True)
        #     procs.append(f)
        #     f = subprocess.Popen("exec taskset -c %d /home/%s/stress %d %d %d" % (i, USER, n, m, i + nr - 8),
        #             preexec_fn=change(UID, UID), shell=True)
        #     procs.append(f)


        for i in range(nr):
            f = subprocess.Popen("exec taskset -c %d-%d /home/%s/stress %d %d %d" % (0, self.nr - 1, USER, n, m, i),
                    preexec_fn=change(UID, UID), shell=True)
            procs.append(f)

        self.perf_ret = app.run(type(self).__name__, self.nr, n, m, iter)

        for f in procs:
            os.kill(f.pid, signal.SIGINT)

        time.sleep(2)
        self.count = 0
        try:
            for path, _, filelist in os.walk("/tmp/count"):
                for filename in filelist:
                    with open(os.path.join(path, filename), "r") as f:
                        line = f.readline()
                        self.count += int(line.strip().split("/")[0])
        except Exception as e:
            print(e)

class Sysdig(Base):
    def start(self):
        self.proc = subprocess.Popen("exec taskset -c %d-%d /home/jeshrz/sysdig/build/userspace/sysdig/sysdig -w /tmp/out.scap" % (0, self.nr - 1), shell=True)
        time.sleep(1)

    def finish(self):
        os.kill(self.proc.pid, signal.SIGINT)
        time.sleep(2)
        subprocess.run("rm -rf /tmp/out.scap", shell=True)
        time.sleep(1)
        p = subprocess.run("dmesg -c", shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.decode("utf-8").split("\n")
        line = lines[-4]
        data = line.split()
        self.n_evts = int(data[-3])
        self.n_recv_evts = int(data[-1])
        self.n_recv_evts = self.n_evts - self.n_recv_evts

class SysdigBlock(Base):
    def start(self):
        self.proc = subprocess.Popen("exec taskset -c %d-%d /home/jeshrz/sysdig-block/build-2/userspace/sysdig/sysdig -w /tmp/out-block.scap" % (0, self.nr - 1), shell=True)
        time.sleep(1)

    def finish(self):
        os.kill(self.proc.pid, signal.SIGINT)
        time.sleep(2)
        subprocess.run("rm -rf /tmp/out-block.scap", shell=True)
        time.sleep(1)
        p = subprocess.run("dmesg -c", shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.decode("utf-8").split("\n")
        line = lines[-4]
        data = line.split()[-1].split(",")
        self.n_evts = int(data[0])
        self.n_recv_evts = int(data[1])
        self.n_recv_evts = self.n_evts - self.n_recv_evts

class SysdigMulti(Base):
    def start(self):
        self.procs = []
        for i in range(self.nr):
            f = subprocess.Popen("exec taskset -c %d-%d /home/jeshrz/sysdig-multi/build/userspace/sysdig/sysdig -w /tmp/out-%d.scap" % (0, self.nr - 1, i), shell=True)
            time.sleep(1)
            self.procs.append(f)


    def finish(self):
        for i in range(self.nr):
            os.kill(self.procs[i].pid, signal.SIGINT)
        time.sleep(2)
        for i in range(self.nr):
            subprocess.run("rm -rf /tmp/out-%d.scap" % i, shell=True)
        p = subprocess.run("dmesg -c", shell=True, stdout=subprocess.PIPE)

        self.n_evts = self.n_recv_evts = 0
        lines = p.stdout.decode("utf-8").split("\n")
        for line in lines:
            if "total_evts" in line:
                data = line.split()
                n_evts = int(data[-3])
                self.n_evts += n_evts
                self.n_recv_evts += n_evts - int(data[-1])

        # line = lines[-4]
        # data = line.split()[-1].split(",")
        # self.n_evts = int(data[0])
        # self.n_recv_evts = int(data[1])
        # self.n_recv_evts = self.n_evts - self.n_recv_evts
        # self.n_evts = self.n_recv_evts = 0

class NoDrop(Base):
    def start(self):
        pass

    def finish(self):
        p = subprocess.run("/home/jeshrz/NoDrop/build/scripts/ctrl/ctrl stat", shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.decode("utf-8").split("\n")
        line = lines[-2]
        data = line.split()
        self.n_evts = int(data[0])
        subprocess.run("/home/jeshrz/NoDrop/build/scripts/ctrl/ctrl clear-stat", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("rm -rf /tmp/nodrop", shell=True)
        subprocess.run("su %s -c \"mkdir /tmp/nodrop\"" % USER, shell=True)
        self.n_recv_evts = self.n_evts
        # for path, _, filelist in os.walk("/tmp/nodrop/count"):
        #     for filename in filelist:
        #         with open(os.path.join(path, filename), "r") as f:
        #             fileline = f.readline()
        #             if fileline:
        #                 self.n_recv_evts += int(fileline)

class Camflow(Base):
    def start(self):
        subprocess.run("rm -rf /tmp/camflow.log", shell=True)
        subprocess.run("systemctl restart camflowd.service", shell=True)
        subprocess.run("camflow --track-user root opaque", shell=True)
        subprocess.run("camflow -a true", shell=True)
        subprocess.run("camflow -e true", shell=True)

    def finish(self):
        pass

class Kaudit(Base):
    def start(self):
        subprocess.run("rm -rf /tmp/audit/*", shell=True)
        subprocess.run("service auditd restart", shell=True, stdout=subprocess.DEVNULL)
        subprocess.run("auditctl -a always,exit -S all -F uid=%d" % UID, shell=True)

        f = subprocess.run(["/usr/bin/ps", "-ef"], stdout=subprocess.PIPE)
        lines = f.stdout.decode("utf-8").split("\n")
        for line in lines:
            if line.startswith("root") and "auditd" in line:
                pid = line.strip().split()[1]
                pid = int(pid)
                subprocess.run("taskset -apc 0-%d %d" % (self.nr - 1, pid), shell=True, stdout=subprocess.DEVNULL)

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
        # p = subprocess.run("aureport --summary", shell=True, stdout=subprocess.PIPE)
        # lines = p.stdout.decode("utf-8").split("\n")
        # for line in lines:
        #     if "Number of events" in line:
        #         n_recv_evts = int(line.split(":")[1].strip())
        #         break
        #
        self.n_evts = n_drop_evts + n_recv_evts
        self.n_recv_evts = n_recv_evts

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
        f = subprocess.run(["/usr/bin/ps", "-ef"], stdout=subprocess.PIPE)
        lines = f.stdout.decode("utf-8").split("\n")
        for line in lines:
            if line.startswith("root") and "lttng-" in line:
                pid = line.strip().split()[1]
                pid = int(pid)
                subprocess.run("taskset -apc 0-%d %d" % (self.nr - 1, pid), shell=True, stdout=subprocess.DEVNULL)

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

        self.n_recv_evts = 0
        self.n_evts = n_drop_evts + self.n_recv_evts

def main(target, app, nr):
    LOOP = 10
    for cfg in CONFIG:
        total_perf_ret, total_count = 0, 0
        total_evts, total_recv_evts = 0, 0
        for i in range(LOOP):
            target.start()
            target.stress(cfg[0], cfg[1], app, nr, i)
            target.finish()
            total_perf_ret += target.perf_ret
            total_count += target.count
            total_evts += target.n_evts
            total_recv_evts += target.n_recv_evts
        print("%d/%d" % cfg, total_perf_ret / LOOP)
        print(total_count / LOOP)
        print(total_recv_evts / LOOP, total_evts / LOOP)
        # print("%d/%d" % cfg, target.n_evts)
        # print(target.count, target.n_recv_evts)

if __name__ == '__main__':
    if os.getuid() != 0:
        print("Run as root")
        exit(0)
    elif len(sys.argv) < 4:
        print("Usage: %s [sysdig|block|multi|nodrop|camflow|lttng|audit] [nginx|redis|openssl] <nrcore>" % sys.argv[0])
        exit(0)

    nr = int(sys.argv[3])

    subprocess.run("mkdir -p /tmp/count", shell=True)
    subprocess.run("chgrp -R %d /tmp/count" % UID, shell=True)
    subprocess.run("chown -R %d /tmp/count" % UID, shell=True)

    if sys.argv[1] == "sysdig":
        target = Sysdig(nr)
    elif sys.argv[1] == "block":
        target = SysdigBlock(nr)
    elif sys.argv[1] == "multi":
        target = SysdigMulti(nr)
        CONFIG = [(0, 10000), (10, 10000), (100, 10000), (1000, 10000), (5000, 10000), (10000, 10000), (10000, 0)]
    elif sys.argv[1] == "nodrop":
        target = NoDrop(nr)
    elif sys.argv[1] == "camflow":
        target = Camflow(nr)
    elif sys.argv[1] == "lttng":
        target = Lttng(nr)
    elif sys.argv[1] == "audit":
        target = Kaudit(nr)
    else:
        target = Base(nr)

    if sys.argv[2] == "nginx":
        app = Nginx()
    elif sys.argv[2] == "redis":
        app = Redis()
    elif sys.argv[2] == "openssl":
        app = Openssl()
    else:
        print("invalid %s" % sys.argv[2])
        exit(-1)

    main(target, app, nr)
