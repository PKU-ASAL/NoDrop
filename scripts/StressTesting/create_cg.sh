#!/bin/bash

set -e

NRCPU=${1:-1}
USER=${2:-`whoami`}

echo NRCPU=$NRCPU USER=$USER

QUOTA=`expr $NRCPU \* 50000`
CPULINE=`expr $NRCPU - 1`

echo QUOTA=$QUOTA CPULINE=$CPULINE

cgcreate -g cpu:openssl
cgcreate -g cpuset:openssl

cgset -r cpu.cfs_quota_us=${QUOTA} openssl
cgset -r cpuset.cpus=0-${CPULINE} openssl
cgset -r cpuset.mems=0 openssl

chgrp -R $USER /sys/fs/cgroup/cpu/openssl
chgrp -R $USER /sys/fs/cgroup/cpuset/openssl

chown -R $USER /sys/fs/cgroup/cpu/openssl
chown -R $USER /sys/fs/cgroup/cpuset/openssl

cgget -g cpu:openssl
cgget -g cpuset:openssl