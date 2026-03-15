#!/usr/bin/env bash
set -euo pipefail

########################################
# Redis end-to-end experiment framework
# Modes:
#   baseline
#   nodrop_count
#   nodrop_compress
#   sysdig_count
#   sysdig_compress
#
# Usage examples:
#   ./run_redis_e2e.sh --config C1 --mode baseline
#   ./run_redis_e2e.sh --config C2 --mode nodrop_count --runs 5
#   ./run_redis_e2e.sh --config C4 --mode all --runs 3
########################################

############################
# User-configurable paths
############################
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDIS_SERVER="${ROOT_DIR}/redis/redis_/src/redis-server"
REDIS_BENCHMARK="${ROOT_DIR}/redis/redis_/src/redis-benchmark"
NODROP_BIN="${NODROP_BIN:-nodrop}"

# NoDrop Lua script for syscall counting
NODROP_COUNT_LUA="${NODROP_COUNT_LUA:-${ROOT_DIR}/../scripts/lua/calc.lua}"

# Sysdig filter: only monitor redis-server
SYSDIG_FILTER='proc.name=redis-server'
SYSDIG_COUNT_CMD_TEMPLATE='taskset -c {CPU} sysdig -c '"${ROOT_DIR}"'/../scripts/lua/calc.lua "{FILTER}" > "{OUT}" 2>&1'
SYSDIG_COMPRESS_CMD_TEMPLATE='taskset -c {CPU} sysdig -z -w "{OUT}" "{FILTER}"'

############################
# Benchmark defaults
############################
RUNS=5
BASE_PORT=6379
REDIS_STARTUP_WAIT=1
SHUTDOWN_WAIT=1

# benchmark params
BENCH_CLIENTS=200
BENCH_REQUESTS=1000000
BENCH_TEST="get"
BENCH_DATA_SIZE=0

# output
RESULT_DIR="${ROOT_DIR}/results/e2e_redis"
mkdir -p "${RESULT_DIR}"

############################
# Parse args
############################
CONFIG=""
MODE=""

usage() {
  cat <<EOF
Usage:
  $0 --config C1|C2|C3|C4 --mode baseline|nodrop_count|nodrop_compress|sysdig_count|sysdig_compress|all [--runs N]

Options:
  --config   Resource config
  --mode     Experiment mode
  --runs     Repeat count (default: ${RUNS})
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG="$2"; shift 2 ;;
    --mode)
      MODE="$2"; shift 2 ;;
    --runs)
      RUNS="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "[ERR] Unknown argument: $1" >&2
      usage
      exit 1 ;;
  esac
done

if [[ -z "${CONFIG}" || -z "${MODE}" ]]; then
  usage
  exit 1
fi

############################
# Helpers
############################
timestamp() {
  date +"%Y%m%d_%H%M%S"
}

log() {
  echo "[$(date +'%F %T')] $*"
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[ERR] command not found: $1" >&2
    exit 1
  }
}

join_by_comma() {
  local IFS=","
  echo "$*"
}

pick_random_core_from_array() {
  local arr=("$@")
  local idx=$((RANDOM % ${#arr[@]}))
  echo "${arr[$idx]}"
}

render_template() {
  local template="$1"
  local cpu="$2"
  local filter="$3"
  local out="$4"

  template="${template//\{CPU\}/${cpu}}"
  template="${template//\{FILTER\}/${filter}}"
  template="${template//\{OUT\}/${out}}"
  echo "${template}"
}

check_prereqs() {
  require_bin taskset
  require_bin awk
  require_bin sed
  require_bin grep
  require_bin shuf
  require_bin python3

  [[ -x "${REDIS_SERVER}" ]] || { echo "[ERR] redis-server not found: ${REDIS_SERVER}" >&2; exit 1; }
  [[ -x "${REDIS_BENCHMARK}" ]] || { echo "[ERR] redis-benchmark not found: ${REDIS_BENCHMARK}" >&2; exit 1; }

  if [[ "${MODE}" == nodrop_* ]]; then
    require_bin "${NODROP_BIN}"
  fi
}

############################
# Config mapping
############################
REDIS_CORES=()
BENCH_CORES=()
INSTANCE_NR=0
TOTAL_MEM_MB=0

setup_config() {
  case "${CONFIG}" in
    C1)
      REDIS_CORES=(0)
      BENCH_CORES=(1 2)
      INSTANCE_NR=1
      TOTAL_MEM_MB=2048
      ;;
    C2)
      REDIS_CORES=(0 1 2 3)
      BENCH_CORES=(4 5 6 7)
      INSTANCE_NR=4
      TOTAL_MEM_MB=8192
      ;;
    C3)
      REDIS_CORES=(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
      BENCH_CORES=(16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31)
      INSTANCE_NR=16
      TOTAL_MEM_MB=32768
      ;;
    C4)
      REDIS_CORES=(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 \
                   16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31)
      BENCH_CORES=(32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 \
                   48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63)
      INSTANCE_NR=32
      TOTAL_MEM_MB=65536
      ;;
    *)
      echo "[ERR] invalid config: ${CONFIG}" >&2
      exit 1
      ;;
  esac

  local need_cores=0
  for c in "${REDIS_CORES[@]}"; do
    (( c > need_cores )) && need_cores=$c
  done
  for c in "${BENCH_CORES[@]}"; do
    (( c > need_cores )) && need_cores=$c
  done
  need_cores=$((need_cores + 1))

  local actual_cores
  actual_cores=$(nproc)
  if (( actual_cores < need_cores )); then
    echo "[ERR] config ${CONFIG} needs at least ${need_cores} CPU cores, but host only has ${actual_cores}" >&2
    exit 1
  fi
}

############################
# Runtime state
############################
WORK_TAG="$(timestamp)_${CONFIG}_${MODE}"
WORK_DIR="${RESULT_DIR}/${WORK_TAG}"
mkdir -p "${WORK_DIR}"

REDIS_PID_FILE="${WORK_DIR}/redis_pids.txt"
MONITOR_PID_FILE="${WORK_DIR}/monitor_pids.txt"
BENCH_RAW_DIR="${WORK_DIR}/bench_raw"
REDIS_CONF_DIR="${WORK_DIR}/redis_conf"
REDIS_DATA_DIR="${WORK_DIR}/redis_data"
mkdir -p "${BENCH_RAW_DIR}" "${REDIS_CONF_DIR}" "${REDIS_DATA_DIR}"

RESULT_CSV="${RESULT_DIR}/summary.csv"
if [[ ! -f "${RESULT_CSV}" ]]; then
  echo "timestamp,config,mode,run,instances,total_mem_mb,per_instance_mem_mb,total_throughput_rps" > "${RESULT_CSV}"
fi

cleanup() {
  set +e

  if [[ -f "${MONITOR_PID_FILE}" ]]; then
    while read -r pid; do
      [[ -n "${pid}" ]] && kill "${pid}" >/dev/null 2>&1 || true
    done < "${MONITOR_PID_FILE}"
  fi

  if [[ "${MODE}" == nodrop_* ]]; then
    "${NODROP_BIN}" stop >/dev/null 2>&1 || true
  fi

  if [[ -f "${REDIS_PID_FILE}" ]]; then
    while read -r pid; do
      [[ -n "${pid}" ]] && kill -INT "${pid}" >/dev/null 2>&1 || true
    done < "${REDIS_PID_FILE}"
  fi

  sleep "${SHUTDOWN_WAIT}"
}
trap cleanup EXIT

############################
# Redis
############################
generate_redis_conf() {
  local idx="$1"
  local port=$((BASE_PORT + idx))
  local core="${REDIS_CORES[$idx]}"
  local per_inst_mem_mb=$((TOTAL_MEM_MB / INSTANCE_NR))
  local conf="${REDIS_CONF_DIR}/redis_${port}.conf"
  local datadir="${REDIS_DATA_DIR}/redis_${port}"
  mkdir -p "${datadir}"

  cat > "${conf}" <<EOF
bind 127.0.0.1
port ${port}
protected-mode no
daemonize no
save ""
appendonly no
dir ${datadir}
dbfilename dump.rdb
maxmemory ${per_inst_mem_mb}mb
maxmemory-policy noeviction
io-threads 1
EOF

  echo "${conf}"
}

start_redis_instances() {
  : > "${REDIS_PID_FILE}"
  log "Starting ${INSTANCE_NR} redis-server instances ..."

  for ((i=0; i<INSTANCE_NR; i++)); do
    local conf
    conf=$(generate_redis_conf "${i}")
    local core="${REDIS_CORES[$i]}"

    taskset -c "${core}" \
      "${REDIS_SERVER}" "${conf}" \
      > "${WORK_DIR}/redis_${i}.log" 2>&1 &
    local pid=$!
    echo "${pid}" >> "${REDIS_PID_FILE}"

    log "  redis[$i] port=$((BASE_PORT+i)) core=${core} pid=${pid}"
  done

  sleep "${REDIS_STARTUP_WAIT}"
}

stop_redis_instances() {
  if [[ -f "${REDIS_PID_FILE}" ]]; then
    while read -r pid; do
      [[ -n "${pid}" ]] && kill -INT "${pid}" >/dev/null 2>&1 || true
    done < "${REDIS_PID_FILE}"
  fi
  sleep "${SHUTDOWN_WAIT}"
  rm -f "${REDIS_PID_FILE}"
}

############################
# Monitor start/stop
############################
start_monitor() {
  : > "${MONITOR_PID_FILE}"

  case "${MODE}" in
    baseline)
      log "Mode=baseline, no monitor started."
      ;;

    nodrop_count)
      [[ -f "${NODROP_COUNT_LUA}" ]] || {
        echo "[ERR] NoDrop count Lua not found: ${NODROP_COUNT_LUA}" >&2
        exit 1
      }
      log "Starting NoDrop with count Lua: ${NODROP_COUNT_LUA}"
      "${NODROP_BIN}" start ${NODROP_COUNT_LUA}
      "${NODROP_BIN}" record none
      ;;

    nodrop_compress)
      log "Starting NoDrop + record compress"
      "${NODROP_BIN}" start
      "${NODROP_BIN}" record compress
      ;;

    sysdig_count)
      if [[ -z "${SYSDIG_COUNT_CMD_TEMPLATE}" ]]; then
        echo "[ERR] SYSDIG_COUNT_CMD_TEMPLATE is empty." >&2
        exit 1
      fi
      local cpu
      cpu=$(pick_random_core_from_array "${REDIS_CORES[@]}")
      local out="${WORK_DIR}/sysdig_count.out"
      local cmd
      cmd=$(render_template "${SYSDIG_COUNT_CMD_TEMPLATE}" "${cpu}" "${SYSDIG_FILTER}" "${out}")
      log "Starting sysdig_count on core ${cpu}"
      log "  cmd: ${cmd}"
      bash -c "exec ${cmd}" &
      echo "$!" >> "${MONITOR_PID_FILE}"
      sleep 1
      ;;

    sysdig_compress)
      if [[ -z "${SYSDIG_COMPRESS_CMD_TEMPLATE}" ]]; then
        echo "[ERR] SYSDIG_COMPRESS_CMD_TEMPLATE is empty." >&2
        exit 1
      fi
      local cpu
      cpu=$(pick_random_core_from_array "${REDIS_CORES[@]}")
      local out="${WORK_DIR}/sysdig_trace.scap.gz"
      local cmd
      cmd=$(render_template "${SYSDIG_COMPRESS_CMD_TEMPLATE}" "${cpu}" "${SYSDIG_FILTER}" "${out}")
      log "Starting sysdig_compress on core ${cpu}"
      log "  cmd: ${cmd}"
      bash -c "exec ${cmd}" &
      echo "$!" >> "${MONITOR_PID_FILE}"
      sleep 1
      ;;

    *)
      echo "[ERR] unsupported mode: ${MODE}" >&2
      exit 1
      ;;
  esac
}

stop_monitor() {
  case "${MODE}" in
    baseline)
      ;;
    nodrop_count|nodrop_compress)
      log "Stopping NoDrop"
      "${NODROP_BIN}" stop || true
      ;;
    sysdig_count|sysdig_compress)
      if [[ -f "${MONITOR_PID_FILE}" ]]; then
        local pid
        pid=$(cat "${MONITOR_PID_FILE}")
        if kill -0 "${pid}" 2>/dev/null; then
          kill -INT "${pid}"
          wait "${pid}" 2>/dev/null || true
        fi
      fi
      ;;
  esac

  sleep "${SHUTDOWN_WAIT}"
  rm -f "${MONITOR_PID_FILE}"
}

############################
# Benchmark
############################
run_one_benchmark_instance() {
  local idx="$1"
  local port=$((BASE_PORT + idx))
  local bench_core="${BENCH_CORES[$idx]}"
  local raw_out="${BENCH_RAW_DIR}/bench_${idx}.txt"

  taskset -c "${bench_core}" \
    "${REDIS_BENCHMARK}" \
      -h 127.0.0.1 \
      -p "${port}" \
      -q \
      -t "${BENCH_TEST}" \
      --csv \
      -d "${BENCH_DATA_SIZE}" \
      -c "${BENCH_CLIENTS}" \
      -n "${BENCH_REQUESTS}" \
      > "${raw_out}" 2>/dev/null
}

parse_benchmark_rps() {
  local file="$1"
  python3 - "$file" <<'PY'
import sys, re
path = sys.argv[1]
txt = open(path, "r", encoding="utf-8", errors="ignore").read().strip()
# typical: "GET","123456.78"
m = re.search(r'"[^"]+"\s*,\s*"([^"]+)"', txt)
if not m:
    print("0")
    sys.exit(0)
try:
    print(float(m.group(1)))
except:
    print("0")
PY
}

run_benchmarks_and_collect_total() {
  rm -f "${BENCH_RAW_DIR}"/bench_*.txt

  local pids=()
  for ((i=0; i<INSTANCE_NR; i++)); do
    run_one_benchmark_instance "${i}" &
    pids+=("$!")
  done

  for pid in "${pids[@]}"; do
    wait "${pid}"
  done

  local total="0"
  for ((i=0; i<INSTANCE_NR; i++)); do
    local f="${BENCH_RAW_DIR}/bench_${i}.txt"
    local rps
    rps=$(parse_benchmark_rps "${f}")
    total=$(python3 - <<PY
a=float("${total}")
b=float("${rps}")
print(a+b)
PY
)
  done

  echo "${total}"
}

############################
# One run
############################
do_single_run() {
  local run_id="$1"

  log "=============================="
  log "Run ${run_id}/${RUNS}  config=${CONFIG}  mode=${MODE}"
  log "=============================="

  start_redis_instances
  start_monitor

  local total_rps
  total_rps=$(run_benchmarks_and_collect_total)

  stop_monitor
  stop_redis_instances

  local per_inst_mem_mb=$((TOTAL_MEM_MB / INSTANCE_NR))
  echo "$(date +'%F %T'),${CONFIG},${MODE},${run_id},${INSTANCE_NR},${TOTAL_MEM_MB},${per_inst_mem_mb},${total_rps}" >> "${RESULT_CSV}"

  log "Run ${run_id} total throughput = ${total_rps} req/s"
}

############################
# Multi-mode
############################
run_mode() {
  local mode="$1"
  MODE="${mode}"

  for ((r=1; r<=RUNS; r++)); do
    do_single_run "${r}"
  done
}

############################
# Main
############################
check_prereqs
setup_config

log "Work dir: ${WORK_DIR}"
log "Config=${CONFIG} Mode=${MODE} Runs=${RUNS}"
log "Redis cores: $(join_by_comma "${REDIS_CORES[@]}")"
log "Bench cores: $(join_by_comma "${BENCH_CORES[@]}")"
log "Instances=${INSTANCE_NR}, TotalMem=${TOTAL_MEM_MB}MB"

if [[ "${MODE}" == "all" ]]; then
  for m in baseline nodrop_count nodrop_compress sysdig_count sysdig_compress; do
    run_mode "${m}"
  done
else
  run_mode "${MODE}"
fi

log "Done. Summary CSV: ${RESULT_CSV}"