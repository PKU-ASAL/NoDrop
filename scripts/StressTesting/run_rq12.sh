#!/bin/bash

# mount tmpfs /tmp -t tmpfs -o size=200g

if [ $# -lt 1 ]; then 
    echo "Usage: $0 <nrcore>"
    exit 1
fi

# TOOL=$1
NR=$1

TOOLS=("nginx" "redis" "openssl")
for TOOL in ${TOOLS[@]}
do
  echo "=========== $TOOL ==========="

  echo "Sysdig-block"
  insmod /home/jeshrz/sysdig-block/build-2/driver/scap.ko
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py block $TOOL $NR
  rmmod scap

  echo "Sysdig"
  insmod /home/jeshrz/sysdig/build/driver/scap.ko
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py sysdig $TOOL $NR
  rmmod scap

  echo "Base"
  insmod /home/jeshrz/sysdig/build-1/driver/scap.ko
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py sysdig $TOOL $NR
  rmmod scap

  echo "NoDrop"
  make -C /home/jeshrz/NoDrop/build load > /dev/null
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py nodrop $TOOL $NR
  rmmod nodrop
done
