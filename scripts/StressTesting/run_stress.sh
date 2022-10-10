#!/bin/bash

set -e

NRCPU=${1:-`nproc`}
USER=${2:-`whoami`}
N=${3:-0}
M=${4:-0}

CPULINE=`expr $NRCPU - 1`

for (( c=0; c<$NRCPU; c++ ))
do
  taskset -c 0-${CPULINE} /home/$USER/stress $N $M $c &
done
