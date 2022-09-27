#!/bin/bash

# mount tmpfs /tmp -t tmpfs -o size=200g

NR=`nproc`

mkdir -p /tmp/count
chgrp -R bench /tmp/count
chown -R bench /tmp/count

echo "Sysdig"
insmod /home/jeshrz/sysdig/build/driver/scap.ko
/home/jeshrz/NoDrop/scripts/StressTesting/test_drop.py sysdig $NR
rmmod scap

echo "NoDrop"
make -C /home/jeshrz/NoDrop/build load > /dev/null
/home/jeshrz/NoDrop/scripts/StressTesting/test_drop.py nodrop $NR
rmmod nodrop

echo "LTTng"
/home/jeshrz/NoDrop/scripts/StressTesting/test_drop.py lttng $NR
ps -ef | grep lttng | awk '{print $2}' | xargs kill

echo Kaudit
mkdir -p /tmp/audit
/home/jeshrz/NoDrop/scripts/StressTesting/test_drop.py audit $NR
auditctl -D
service auditd stop