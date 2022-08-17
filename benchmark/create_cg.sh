#!/bin/bash

# TOTAL_CPU=47
# CPULINE=32
# CPULINE_BEFORE=`expr $CPULINE - 1`
TOTAL_CPU=1
CPULINE=1
CPULINE_BEFORE=`expr $CPULINE - 1`

cgcreate -g cpuset:/perf
cgcreate -g cpuset:/app
chown -R jeshrz /sys/fs/cgroup/cpuset/app/
chgrp -R jeshrz /sys/fs/cgroup/cpuset/app/

cgset -r cpuset.mems=0 perf
cgset -r cpuset.mems=0  app

cgset -r cpuset.cpus=$CPULINE-$TOTAL_CPU perf
cgset -r cpuset.cpus=0-$CPULINE_BEFORE app
