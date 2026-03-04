#!/bin/bash
set -e

#####################################
# Arguments
#####################################

WORKLOAD=$1     # nginx | redis | postmark
MODE=$2         # baseline | sysdig | nodrop | nodrop_lua

if [ -z "$WORKLOAD" ] || [ -z "$MODE" ]; then
    echo "Usage: sudo $0 {nginx|redis|postmark} {baseline|sysdig|nodrop|nodrop_lua}"
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

# 客户端（wrk / memtier）
export CLIENT_CPU_CORES="1-7"

# sysdig（仅 sysdig 需要）
MONITOR_CPU_CORES="0"

# workload env
export NGINX_CPU_CORE=${TARGET_CPU_CORE}
export WRK_CPU_CORES=${CLIENT_CPU_CORES}

export REDIS_CPU_CORE=${TARGET_CPU_CORE}
export MEMTIER_CPU_CORES=${CLIENT_CPU_CORES}

#####################################
# Memory cgroup (v1 memory controller)
#####################################

# 只限制被测 Redis 的内存
export REDIS_MEM_LIMIT_BYTES=$((2 * 1024 * 1024 * 1024))   # 2GB
export REDIS_MEM_CGROUP_NAME="redis_bench"                 # /sys/fs/cgroup/memory/redis_bench

MEM_CGROUP_BASE="/sys/fs/cgroup/memory"
MEM_CGROUP_PATH="${MEM_CGROUP_BASE}/${REDIS_MEM_CGROUP_NAME}"

init_mem_cgroup() {
    if [ ! -d "${MEM_CGROUP_BASE}" ]; then
        echo "[WARN] ${MEM_CGROUP_BASE} not found; skip memory limit."
        return 0
    fi

    # 创建 cgroup
    mkdir -p "${MEM_CGROUP_PATH}"

    # 设置 2GB 限制
    echo "${REDIS_MEM_LIMIT_BYTES}" > "${MEM_CGROUP_PATH}/memory.limit_in_bytes" || true

    # 尽量减少 swap 干扰（不是硬禁用）
    if [ -f "${MEM_CGROUP_PATH}/memory.swappiness" ]; then
        echo 0 > "${MEM_CGROUP_PATH}/memory.swappiness" || true
    fi

    echo "[*] Memory cgroup ready: ${MEM_CGROUP_PATH}"
    echo "    limit_in_bytes=$(cat ${MEM_CGROUP_PATH}/memory.limit_in_bytes 2>/dev/null || echo '?')"
}

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
    sudo pkill -9 redis-server || true
    sleep 1

    # 可选：清理 cgroup（不清也行，方便复用）
    # rmdir 只有空目录才能删；tasks 里不能有进程
    if [ -d "${MEM_CGROUP_PATH}" ]; then
        # best-effort: ensure no tasks remain
        # (if any, they should be killed by pkill redis-server above)
        rmdir "${MEM_CGROUP_PATH}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

#####################################
# Init memory cgroup
#####################################

# 只在 redis workload 下强制初始化（你也可以对 nginx/postmark 做同样逻辑）
if [ "${WORKLOAD}" = "redis" ]; then
    init_mem_cgroup
fi

#####################################
# Start monitoring
#####################################

echo "======================================"
echo " Workload   : $WORKLOAD"
echo " Mode       : $MODE"
echo " Target CPU : core ${TARGET_CPU_CORE}"
echo " Client CPU : cores ${CLIENT_CPU_CORES}"
echo " Mem cgroup : ${MEM_CGROUP_PATH} (limit=${REDIS_MEM_LIMIT_BYTES})"
echo "======================================"

case "$MODE" in
    baseline)
        echo "[*] Baseline: no monitoring"
        ;;

    sysdig)
        echo "[*] Starting sysdig (userspace, same core as target)"
        taskset -c ${MONITOR_CPU_CORES} \
            sysdig -z -w /tmp/sysdig-redis.scap.gz "proc.name=redis-server" \
            &
        sleep 2
        ;;

    nodrop)
        echo "[*] Starting NoDrop (kernel, inline)"
        $NODROP_CTRL start
        $NODROP_CTRL record compress
        sleep 1
        ;;

    # nodrop_lua)
    #     echo "[*] Starting NoDrop with Lua (kernel, inline)"
    #     $NODROP_CTRL start ${NODROP_CHISEL}
    #     sleep 1
    #     ;;

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