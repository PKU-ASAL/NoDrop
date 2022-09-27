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

  # echo "Camflow"
  # systemctl start camflowd.service
  # /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py camflow $TOOL $NR
  # rm -rf /tmp/audit.log

  echo "Sysdig-Multi"
  insmod /home/jeshrz/sysdig-multi/build/driver/scap.ko
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py multi $TOOL $NR
  sleep 10s
  rmmod scap

  echo "Base"
  insmod /home/jeshrz/sysdig/build/driver/scap.ko
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py base $TOOL $NR
  sleep 10s
  rmmod scap

  echo "Sysdig"
  insmod /home/jeshrz/sysdig/build/driver/scap.ko
  sleep 10s
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py sysdig $TOOL $NR
  rmmod scap

  echo "Sysdig-Block"
  insmod /home/jeshrz/sysdig-block/build-2/driver/scap.ko
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py block $TOOL $NR
  sleep 10s
  rmmod scap

  echo "NoDrop"
  make -C /home/jeshrz/NoDrop/build load > /dev/null
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py nodrop $TOOL $NR
  rmmod nodrop

  echo "LTTng"
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py lttng $TOOL $NR
  ps -ef | grep lttng | awk '{print $2}' | xargs kill
  sleep 5s

  echo Kaudit
  mkdir -p /tmp/audit
  /home/jeshrz/NoDrop/scripts/StressTesting/test_perf.py audit $TOOL $NR
  auditctl -D
  service auditd stop
done

