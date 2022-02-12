import struct
import os
import matplotlib.pyplot as plt
import numpy as np
import threading

class MyThread(threading.Thread):
    def __init__(self, func, args=()):
        super(MyThread, self).__init__()
        self.func = func
        self.args = args
    def run(self):
        self.result = self.func(*self.args)
    def get_result(self):
        threading.Thread.join(self)  # 等待线程执行完毕
        try:
            return self.result
        except Exception:
            return None

def do_count(filename):
    count = 0
    evts = {}
    pos = 0
    with open(filename, "rb") as f:
        f.seek(-4, 2)
        num_data = f.read(4)
        num = struct.unpack('<I', num_data)[0]
        f.seek(0, 0)
        for i in range(num):
            # print(hex(pos))
            hdr_data = f.read(32)
            ts, tid, sz, nargs, etype, magic = struct.unpack("<QQLLLL", hdr_data)

            if magic != 0xCAFEBABE:
                print(filename, i, hex(pos), hex(magic))
                break

            # print(ts, tid, sz, nargs, etype)

            ts = ts // 1e8
            evts[ts] = evts.get(ts, 0) + 1
            count += 1

            f.seek(sz - 32, 1)
            pos += sz
        # lens = []
        # for i in range(nargs):
        #     arg_len_i = f.read(2)
        #     arg_len = struct.unpack('H', arg_len_i)
        #     lens.append(arg_len)
    return (count, evts)
        



# def do_count(file):
#     count = 0
#     evts = {}
#     es = set()
#     with open(file, "r") as f:
#         for line in f.readlines():
#             try:
#                 data = line.split(" ")
#                 tmp = data[0].split("+")
#                 sec = int(tmp[0][1:])
#                 usec = int(tmp[1][0:-1])
#                 tsp = int((sec + usec / 1000000) * 10)
#                 core = int(data[2][0:-1])
#                 tmp = data[3].split(',')
#                 eid = int(tmp[0][4:])
#                 evid = "%d+%d" % (core, eid)
#                 if tsp not in evts:
#                     evts[tsp] = 0
#                 evts[tsp] += 1
#                 if evid in es:
#                     print(file, evid)
#                 else:
#                     es.add(evid)
#                     count += 1
#             except:
#                 continue
#     return (count, evts, es)

def main():
    files = []
    for (dirpath, dirnames, filenames) in os.walk("."):
        for s in filenames:
            if s[-4:] == ".buf":
                files.append(s)
        break
    
    pool = []
    for file in files:
        thr = MyThread(do_count, (file,))
        thr.start()
        pool.append(thr)
    
    for thr in pool:
        thr.join()
    
    evts = {}
    count = 0
    for thr in pool:
        ret = thr.get_result()
        count += ret[0]
        for ev in ret[1]:
            if ev not in evts:
                evts[ev] = 0
            evts[ev] += ret[1][ev]
    
    x = range(100)
    y = []
    idx = []
    for i in evts:
        idx.append(i)
    idx.sort()
    for i in range(100):
        y.append(evts.get(idx[0] + i, 0))
    plt.figure(figsize=(16, 5))
    plt.plot(x, y)
    plt.xlabel("Time (100ms)")
    plt.ylabel("Events number")
    # plt.savefig("data1.png")
    plt.show()

# do_count("57945.buf")
main()

# evts = {}
# count1 = 0
# count2 = 0
# all_e = set()
# mn = 10e9
# mx = 0
# for file in files:
#     with open(file, "r") as f:
#         try:
#             es = f.readline().split()
#             count1 += len(es)
#             count2 += int(f.readline())
#             for e in es:
#                 if int(e) in all_e:
#                     print(int(e))
#                 all_e.add(int(e))
#         except:
#             print(file)
        # for line in f.readlines():
        #     data = line.split(",")
        #     tsp = int(data[1]) * 10 + int(int(data[2]) / 100000)
        #     #tsp = data[1] + "+" + str(int(int(data[2]) / 100000))
        #     if tsp not in evts:
        #         evts[tsp] = []
        #     evts[tsp].append(int(data[0]))
        #     count += 1
        #     mn = min(mn, int(data[0]))
        #     mx = max(mx, int(data[0]))

# print("----------------------------")
# for i in range(count1):
#     if i not in all_e:
#         print(i)
# print(count1, count2)
# print(count, mx - mn + 1)
# x = range(len(evts))
# y = []
# idx = []
# for i in evts:
#   idx.append(i)
# idx.sort()
# for i in idx:
#   y.append(len(evts[i]))

# plt.figure(figsize=(16, 5))
# plt.plot(x, y)
# plt.xlabel("Time (100ms)")
# plt.ylabel("Events number")
# # x_ticks = np.arange(0, len(evts), 1000)
# # plt.xticks(x_ticks)
# # plt.legend(loc="best")
# plt.show()
