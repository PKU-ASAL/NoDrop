#!/bin/bash
SLEEP_TIME=5
CUR=`pwd`
$CUR/StressTesting/test.sh

sleep 2s
# 2 7 12 17 22 27
for i in {1..6}
do
    $CUR/StressTesting/attacker &
    sleep ${SLEEP_TIME}s
done