#!/bin/bash
set -e

#####################################
# Arguments
#####################################

WORKLOAD=$1     # nginx | redis
MODE=$2         # baseline | sysdig | nodrop | nodrop_lua

if [ -z "$WORKLOAD" ] || [ -z "$MODE" ]; then
    echo "Usage: sudo $0 {nginx|redis} {baseline|sysdig|nodrop|nodrop_lua}"
    exit 1
fi

#####################################
# Paths
#####################################

NGINX_TEST_SCRIPT=./test_nginx_cg.py
REDIS_TEST_SCRIPT=./test_redis.py
POSTMARK_TEST_SCRIPT=./test_postmark.py

SYSDIG_CHISEL=~/test.lua
NODROP_CHISEL=~/test.lua
NODROP_CTRL=~/NoDrop/build/scripts/ctrl/ctrl

#####################################
# CPU layout (C1 = 1 core)
#####################################

# 被测应用
export TARGET_CPU_CORE=0

# 客户端（wrk / redis-benchmark）
export CLIENT_CPU_CORES="1-2"

# sysdig（仅 sysdig 需要）
MONITOR_CPU_CORES="0"

# workload env
export NGINX_CPU_CORE=${TARGET_CPU_CORE}
export WRK_CPU_CORES=${CLIENT_CPU_CORES}

export REDIS_CPU_CORE=${TARGET_CPU_CORE}
export MEMTIER_CPU_CORES=${CLIENT_CPU_CORES}

#####################################
# Logs
#####################################

LOGDIR=./results/${WORKLOAD}
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE=${LOGDIR}/${MODE}_${TIMESTAMP}.log

mkdir -p ${LOGDIR}

#####################################
# Checks
#####################################

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root"
    exit 1
fi

#####################################
# Cleanup
#####################################

cleanup() {
    echo "[*] Cleaning up..."

    pkill -f sysdig || true
    $NODROP_CTRL stop 2>/dev/null || true

    sleep 1
}
trap cleanup EXIT

#####################################
# Start monitoring
#####################################

echo "======================================"
echo " Workload   : $WORKLOAD"
echo " Mode       : $MODE"
echo " Target CPU : core ${TARGET_CPU_CORE}"
echo " Client CPU : cores ${CLIENT_CPU_CORES}"
echo "======================================"

case "$MODE" in
    baseline)
        echo "[*] Baseline: no monitoring"
        ;;

    sysdig)
        echo "[*] Starting sysdig (userspace, isolated cores)"
        taskset -c ${MONITOR_CPU_CORES} \
            sysdig -c ${SYSDIG_CHISEL} \
            &
        sleep 2
        ;;

    nodrop)
        echo "[*] Starting NoDrop (kernel, inline)"
        $NODROP_CTRL start
        sleep 1
        ;;

    nodrop_lua)
        echo "[*] Starting NoDrop with Lua (kernel, inline)"
        $NODROP_CTRL start ${NODROP_CHISEL}
        sleep 1
        ;;

    *)
        echo "[ERROR] Unknown mode: $MODE"
        exit 1
        ;;
esac

#####################################
# Run workload
#####################################

case "$WORKLOAD" in
    nginx)
        python3 ${NGINX_TEST_SCRIPT} | tee ${LOGFILE}
        ;;

    redis)
        python3 ${REDIS_TEST_SCRIPT} | tee ${LOGFILE}
        ;;
    postmark)
        python3 ${POSTMARK_TEST_SCRIPT} | tee ${LOGFILE}
        ;;
    *)
        echo "[ERROR] Unknown workload: $WORKLOAD"
        exit 1
        ;;
esac

echo "[*] Benchmark finished"
