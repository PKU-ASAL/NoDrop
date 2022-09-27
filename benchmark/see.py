#!env /bin/python3

import os
import sys

if __name__ == "__main__":
    target = sys.argv[1]
    app = sys.argv[2]
    nrcpu = sys.argv[3]
    n = sys.argv[4]
    m = sys.argv[5]
    filename = "%s-%s-%s-%s-%s.out" % (target, app, nrcpu, n, m)

    results = []
    for i in range(10):
        name = "%s.%d" % (filename, i)
        with open(name, "r") as f:
            lines = f.readlines()
            results.append(float(lines[-5]))
    
    for res in results:
        print(res)
    

