#!/bin/python3

import bt2
import os, sys
import time
import signal
import subprocess

UID = 1000
USER = "jeshrz"

CONFIG = [(10, 10000), (50, 10000), (100, 10000), (500, 10000), (1000, 10000), (5000, 10000), (10000, 10000)]
# CONFIG = [(10000, 10000)]

def change(uid, gid):
    def result():
        os.setgid(gid)
        os.setuid(uid)
    return result


class Nginx:
    def run(self):
        f = subprocess.run("./test_nginx_cg.py", shell=True, stdout=subprocess.PIPE)
        # f = subprocess.run("./test_nginx_cg.py", shell=True)
        lines = f.stdout.decode("utf-8").split("\n")
        line = lines[-3]
        ret = float(line.strip().split()[1])
        return ret

class Redis:
    def run(self):
        f = subprocess.run("./test_redis.py", shell=True, stdout=subprocess.PIPE)
        lines = f.stdout.decode("utf-8").split("\n")
        line = lines[-3]
        ret = float(line.strip().split()[1])
        return ret

class Openssl:
    def run(self):
        f = subprocess.run("./test_openssl.py", shell=True, stdout=subprocess.PIPE)
        lines = f.stdout.decode("utf-8").split("\n")
        line = lines[-3]
        ret = float(line.strip().split()[1])
        return ret


class Base:
    def start(self):
        pass

    def finish(self):
        self.n_evts = self.n_recv_evts = 0

    def stress(self, n, m, app, nr):
        subprocess.run("rm -rf /tmp/count/*", shell=True)

        procs = []
        for i in range(nr):
            f = subprocess.Popen("exec taskset -c %d /home/%s/stress %d %d %d" % (i, USER, n, m, i),
                    preexec_fn=change(UID, UID), shell=True)
            procs.append(f)

        self.perf_ret = app.run()

        for i in range(nr):
            os.kill(procs[i].pid, signal.SIGINT)

        time.sleep(1)
        # self.count = 0
        # for path, _, filelist in os.walk("/tmp/count"):
        #     for filename in filelist:
        #         with open(os.path.join(path, filename), "r") as f:
        #             line = f.readline()
        #             self.count += int(line.strip().split("/")[0])

class Sysdig(Base):
    def start(self):
        self.proc = subprocess.Popen("exec cgexec -g cpuset:app /home/jeshrz/sysdig/build/userspace/sysdig/sysdig -w /tmp/out.scap", shell=True)
        time.sleep(1)

    def finish(self):
        os.kill(self.proc.pid, signal.SIGINT)
        time.sleep(1)
        subprocess.run("rm -rf /tmp/out.scap", shell=True)
        # time.sleep(1)
        # p = subprocess.run("dmesg -c", shell=True, stdout=subprocess.PIPE)
        # lines = p.stdout.decode("utf-8").split("\n")
        # line = lines[-4]
        # data = line.split()
        # self.n_evts = int(data[-3])
        # self.n_recv_evts = int(data[-1])
        # self.n_recv_evts = self.n_evts - self.n_recv_evts

class SysdigBlock(Base):
    def start(self):
        self.proc = subprocess.Popen("exec cgexec -g cpuset:app /home/jeshrz/sysdig-block/build-2/userspace/sysdig/sysdig -w /tmp/out-block.scap", shell=True)
        time.sleep(1)

    def finish(self):
        os.kill(self.proc.pid, signal.SIGINT)
        time.sleep(1)
        subprocess.run("rm -rf /tmp/out-block.scap", shell=True)
        # time.sleep(1)
        # p = subprocess.run("dmesg -c", shell=True, stdout=subprocess.PIPE)
        # lines = p.stdout.decode("utf-8").split("\n")
        # line = lines[-4]
        # data = line.split()
        # self.n_evts = int(data[-3])
        # self.n_recv_evts = int(data[-1])
        # self.n_recv_evts = self.n_evts - self.n_recv_evts

class NoDrop(Base):
    def start(self):
        pass

    def finish(self):
        p = subprocess.run("/home/jeshrz/NoDrop/build/scripts/ctrl/ctrl stat", shell=True, stdout=subprocess.PIPE)
        # lines = p.stdout.decode("utf-8").split("\n")
        # line = lines[-2]
        # data = line.split()
        # self.n_evts = int(data[0])
        subprocess.run("/home/jeshrz/NoDrop/build/scripts/ctrl/ctrl clear-stat", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("rm -rf /tmp/nodrop", shell=True)
        subprocess.run("su %s -c \"mkdir /tmp/nodrop\"" % USER, shell=True)
        # self.n_recv_evts = 0
        # for path, _, filelist in os.walk("/tmp/nodrop/count"):
        #     for filename in filelist:
        #         with open(os.path.join(path, filename), "r") as f:
        #             fileline = f.readline()
        #             if fileline:
        #                 self.n_recv_evts += int(fileline)


def main(target, app, nr):
    for cfg in CONFIG:
        target.start()
        target.stress(cfg[0], cfg[1], app, nr)
        target.finish()
        print("%d/%d" % cfg, target.perf_ret)
        # print("%d/%d" % cfg, target.n_evts)
        # print(target.count, target.n_recv_evts)

if __name__ == '__main__':
    if os.getuid() != 0:
        print("Run as root")
        exit(0)
    elif len(sys.argv) < 4:
        print("Usage: %s [sysdig|block|nodrop|camflow] [nginx|redis|openssl] <nrcore>" % sys.argv[0])
        exit(0)

    nr = int(sys.argv[3])

    subprocess.run("mkdir -p /tmp/count", shell=True)
    subprocess.run("chgrp -R %d /tmp/count" % UID, shell=True)
    subprocess.run("chown -R %d /tmp/count" % UID, shell=True)

    if sys.argv[1] == "sysdig":
        target = Sysdig()
    elif sys.argv[1] == "block":
        target = SysdigBlock()
    elif sys.argv[1] == "nodrop":
        target = NoDrop()
    elif sys.argv[1] == "camflow":
        # TODO
        print("no implement")
        exit(0)
    else:
        target = Base()

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
