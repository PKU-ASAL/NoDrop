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
#   ./run_redis_e2e.sh --config C1 --mode sysdig_compress --runs 5 --no-keep-artifacts
#   ./run_redis_e2e.sh --config C1 --mode nodrop_compress --runs 5 --keep-artifacts
########################################

############################
# User-configurable paths
############################
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDIS_SERVER="${ROOT_DIR}/redis/redis_/src/redis-server"
REDIS_BENCHMARK="${ROOT_DIR}/redis/redis_/src/redis-benchmark"
NODROP_BIN="${NODROP_BIN:-nodrop}"
SYSDIG_BIN="${SYSDIG_BIN:-sysdig}"

# NoDrop default output directory
NODROP_STORE_DIR="${NODROP_STORE_DIR:-/tmp/nodrop}"

# NoDrop Lua script for syscall counting
NODROP_COUNT_LUA="${NODROP_COUNT_LUA:-${ROOT_DIR}/../scripts/lua/calc.lua}"

# Sysdig filter: only monitor redis-server and only ">" direction events
SYSDIG_FILTER='proc.name=redis-server and evt.dir=>'
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

# artifact retention
# 0: delete large trace artifacts after statistics are collected
# 1: keep large trace artifacts
KEEP_ARTIFACTS=0

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
  $0 --config C1|C2|C3|C4 --mode baseline|nodrop_count|nodrop_compress|sysdig_count|sysdig_compress|all [--runs N] [--keep-artifacts|--no-keep-artifacts]

Options:
  --config              Resource config
  --mode                Experiment mode
  --runs                Repeat count (default: ${RUNS})
  --keep-artifacts      Keep large trace files after collecting statistics
  --no-keep-artifacts   Delete large trace files after collecting statistics (default)

Notes:
  Always kept:
    - bench_raw/
    - sysdig_count.out

  Controlled by --keep-artifacts:
    - sysdig_trace.scap.gz
    - sysdig_trace.scap
    - NoDrop *.buf.gz
    - NoDrop *.buf
    - NoDrop *.log
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
    --keep-artifacts)
      KEEP_ARTIFACTS=1; shift ;;
    --no-keep-artifacts)
      KEEP_ARTIFACTS=0; shift ;;
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

REQUESTED_MODE="${MODE}"

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

get_size_bytes() {
  local f="$1"
  if [[ -f "${f}" ]]; then
    stat -c '%s' "${f}"
  else
    echo "0"
  fi
}

safe_wc_l() {
  wc -l | awk '{print $1}'
}

check_prereqs() {
  require_bin taskset
  require_bin awk
  require_bin sed
  require_bin grep
  require_bin shuf
  require_bin python3
  require_bin stat
  require_bin sort
  require_bin comm
  require_bin gzip

  [[ -x "${REDIS_SERVER}" ]] || { echo "[ERR] redis-server not found: ${REDIS_SERVER}" >&2; exit 1; }
  [[ -x "${REDIS_BENCHMARK}" ]] || { echo "[ERR] redis-benchmark not found: ${REDIS_BENCHMARK}" >&2; exit 1; }

  if [[ "${REQUESTED_MODE}" == "all" || "${REQUESTED_MODE}" == nodrop_* ]]; then
    require_bin "${NODROP_BIN}"
  fi

  if [[ "${REQUESTED_MODE}" == "all" || "${REQUESTED_MODE}" == sysdig_* ]]; then
    require_bin "${SYSDIG_BIN}"
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
WORK_TAG="$(timestamp)_${CONFIG}_${REQUESTED_MODE}"
WORK_DIR="${RESULT_DIR}/${WORK_TAG}"
mkdir -p "${WORK_DIR}"

# These variables are updated for each mode/run
RUN_DIR=""
REDIS_PID_FILE=""
MONITOR_PID_FILE=""
BENCH_RAW_DIR=""
REDIS_CONF_DIR=""
REDIS_DATA_DIR=""
NODROP_BEFORE_LIST=""
NODROP_AFTER_LIST=""
NODROP_NEW_LIST=""

# artifact stats for current run
ARTIFACT_FILE_COUNT=0
TOTAL_EVENT_COUNT=0
TOTAL_COMPRESSED_BYTES=0
TOTAL_UNCOMPRESSED_BYTES=0

RESULT_CSV="${RESULT_DIR}/summary.csv"
ARTIFACT_CSV="${RESULT_DIR}/artifact_stats.csv"

SUMMARY_HEADER="timestamp,config,mode,run,instances,total_mem_mb,per_instance_mem_mb,total_throughput_rps,artifact_file_count,total_event_count,total_compressed_bytes,total_uncompressed_bytes"
ARTIFACT_HEADER="timestamp,config,mode,run,source,artifact_index,compressed_bytes,uncompressed_bytes,event_count,kept,status"

if [[ ! -f "${RESULT_CSV}" ]]; then
  echo "${SUMMARY_HEADER}" > "${RESULT_CSV}"
fi

if [[ ! -f "${ARTIFACT_CSV}" ]]; then
  echo "${ARTIFACT_HEADER}" > "${ARTIFACT_CSV}"
fi

setup_run_dirs() {
  local mode="$1"
  local run_id="$2"

  RUN_DIR="${WORK_DIR}/${mode}/run_${run_id}"
  REDIS_PID_FILE="${RUN_DIR}/redis_pids.txt"
  MONITOR_PID_FILE="${RUN_DIR}/monitor_pids.txt"
  BENCH_RAW_DIR="${RUN_DIR}/bench_raw"
  REDIS_CONF_DIR="${RUN_DIR}/redis_conf"
  REDIS_DATA_DIR="${RUN_DIR}/redis_data"
  NODROP_BEFORE_LIST="${RUN_DIR}/nodrop_before.lst"
  NODROP_AFTER_LIST="${RUN_DIR}/nodrop_after.lst"
  NODROP_NEW_LIST="${RUN_DIR}/nodrop_new.lst"

  mkdir -p "${RUN_DIR}" "${BENCH_RAW_DIR}" "${REDIS_CONF_DIR}" "${REDIS_DATA_DIR}"

  ARTIFACT_FILE_COUNT=0
  TOTAL_EVENT_COUNT=0
  TOTAL_COMPRESSED_BYTES=0
  TOTAL_UNCOMPRESSED_BYTES=0
}

cleanup() {
  set +e

  if [[ -n "${MONITOR_PID_FILE:-}" && -f "${MONITOR_PID_FILE}" ]]; then
    while read -r pid; do
      [[ -n "${pid}" ]] && kill "${pid}" >/dev/null 2>&1 || true
    done < "${MONITOR_PID_FILE}"
  fi

  if [[ "${MODE:-}" == nodrop_* ]]; then
    "${NODROP_BIN}" stop >/dev/null 2>&1 || true
  fi

  if [[ -n "${REDIS_PID_FILE:-}" && -f "${REDIS_PID_FILE}" ]]; then
    while read -r pid; do
      [[ -n "${pid}" ]] && kill -INT "${pid}" >/dev/null 2>&1 || true
    done < "${REDIS_PID_FILE}"
  fi

  sleep "${SHUTDOWN_WAIT}" || true
}
trap cleanup EXIT

############################
# Redis
############################
generate_redis_conf() {
  local idx="$1"
  local port=$((BASE_PORT + idx))
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
      > "${RUN_DIR}/redis_${i}.log" 2>&1 &
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
# Artifact statistics
############################
append_artifact_stat() {
  local source="$1"
  local artifact_index="$2"
  local compressed_bytes="$3"
  local uncompressed_bytes="$4"
  local event_count="$5"
  local kept="$6"
  local status="$7"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date +'%F %T')" "${CONFIG}" "${MODE}" "${CURRENT_RUN_ID}" \
    "${source}" "${artifact_index}" "${compressed_bytes}" "${uncompressed_bytes}" \
    "${event_count}" "${kept}" "${status}" \
    >> "${ARTIFACT_CSV}"
}

add_artifact_totals() {
  local compressed_bytes="$1"
  local uncompressed_bytes="$2"
  local event_count="$3"

  ARTIFACT_FILE_COUNT=$((ARTIFACT_FILE_COUNT + 1))
  TOTAL_COMPRESSED_BYTES=$((TOTAL_COMPRESSED_BYTES + compressed_bytes))
  TOTAL_UNCOMPRESSED_BYTES=$((TOTAL_UNCOMPRESSED_BYTES + uncompressed_bytes))
  TOTAL_EVENT_COUNT=$((TOTAL_EVENT_COUNT + event_count))
}

snapshot_nodrop_outputs_before() {
  mkdir -p "${NODROP_STORE_DIR}"

  find "${NODROP_STORE_DIR}" -maxdepth 1 -type f -name '*.buf.gz' -printf '%f\n' \
    2>/dev/null | sort > "${NODROP_BEFORE_LIST}" || true
}

snapshot_nodrop_outputs_after() {
  mkdir -p "${NODROP_STORE_DIR}"

  find "${NODROP_STORE_DIR}" -maxdepth 1 -type f -name '*.buf.gz' -printf '%f\n' \
    2>/dev/null | sort > "${NODROP_AFTER_LIST}" || true

  comm -13 "${NODROP_BEFORE_LIST}" "${NODROP_AFTER_LIST}" > "${NODROP_NEW_LIST}" || true
}

collect_sysdig_compress_stats() {
  local gz_path="${RUN_DIR}/sysdig_trace.scap.gz"
  local scap_path="${RUN_DIR}/sysdig_trace.scap"
  local artifact_index=1
  local compressed_bytes=0
  local uncompressed_bytes=0
  local event_count=0
  local kept="no"
  local status="missing"

  if [[ ! -f "${gz_path}" ]]; then
    append_artifact_stat "sysdig" "${artifact_index}" 0 0 0 "${kept}" "${status}"
    return 0
  fi

  compressed_bytes=$(get_size_bytes "${gz_path}")

  # Keep .gz while decompressing, because we need compressed size and may need to keep the artifact.
  if gzip -dkf "${gz_path}" >/dev/null 2>&1; then
    status="ok"
  else
    status="decompress_failed"
    append_artifact_stat "sysdig" "${artifact_index}" "${compressed_bytes}" 0 0 "${kept}" "${status}"
    if (( KEEP_ARTIFACTS == 0 )); then
      rm -f "${gz_path}" "${scap_path}"
    fi
    return 0
  fi

  uncompressed_bytes=$(get_size_bytes "${scap_path}")

  if [[ -f "${scap_path}" ]]; then
    event_count=$("${SYSDIG_BIN}" -r "${scap_path}" -p "%evt.num %evt.dir" 2>/dev/null | safe_wc_l || echo 0)
  fi

  add_artifact_totals "${compressed_bytes}" "${uncompressed_bytes}" "${event_count}"

  if (( KEEP_ARTIFACTS == 1 )); then
    kept="yes"
  else
    kept="no"
    rm -f "${gz_path}" "${scap_path}"
  fi

  append_artifact_stat "sysdig" "${artifact_index}" "${compressed_bytes}" "${uncompressed_bytes}" "${event_count}" "${kept}" "${status}"
}

collect_nodrop_compress_stats() {
  snapshot_nodrop_outputs_after

  local artifact_dir="${RUN_DIR}/nodrop_artifacts"
  mkdir -p "${artifact_dir}"

  local artifact_index=0

  if [[ ! -s "${NODROP_NEW_LIST}" ]]; then
    append_artifact_stat "nodrop" 0 0 0 0 "no" "missing"
    return 0
  fi

  while read -r fname; do
    [[ -z "${fname}" ]] && continue

    artifact_index=$((artifact_index + 1))

    local src_gz="${NODROP_STORE_DIR}/${fname}"
    local local_gz="${artifact_dir}/${fname}"
    local local_buf="${local_gz%.gz}"
    local local_log="${local_buf%.buf}.log"

    local compressed_bytes=0
    local uncompressed_bytes=0
    local event_count=0
    local kept="no"
    local status="ok"

    if [[ ! -f "${src_gz}" ]]; then
      append_artifact_stat "nodrop" "${artifact_index}" 0 0 0 "${kept}" "missing"
      continue
    fi

    cp -f "${src_gz}" "${local_gz}"
    compressed_bytes=$(get_size_bytes "${local_gz}")

    if gzip -dkf "${local_gz}" >/dev/null 2>&1; then
      uncompressed_bytes=$(get_size_bytes "${local_buf}")
    else
      status="decompress_failed"
      append_artifact_stat "nodrop" "${artifact_index}" "${compressed_bytes}" 0 0 "${kept}" "${status}"
      if (( KEEP_ARTIFACTS == 0 )); then
        rm -f "${local_gz}" "${local_buf}" "${local_log}"
        rm -f "${src_gz}"
      fi
      continue
    fi

    if [[ -f "${local_buf}" ]]; then
      (
        cd "${artifact_dir}"
        "${NODROP_BIN}" parse "$(basename "${local_buf}")" >/dev/null 2>&1 || true
      )
    fi

    if [[ -f "${local_log}" ]]; then
      event_count=$(grep -E '^[0-9]+ [0-9]+ \([0-9]+\):' "${local_log}" 2>/dev/null | safe_wc_l || echo 0)
    else
      status="parse_log_missing"
      event_count=0
    fi

    add_artifact_totals "${compressed_bytes}" "${uncompressed_bytes}" "${event_count}"

    if (( KEEP_ARTIFACTS == 1 )); then
      kept="yes"
    else
      kept="no"
      rm -f "${local_gz}" "${local_buf}" "${local_log}"
      rm -f "${src_gz}"
    fi

    append_artifact_stat "nodrop" "${artifact_index}" "${compressed_bytes}" "${uncompressed_bytes}" "${event_count}" "${kept}" "${status}"
  done < "${NODROP_NEW_LIST}"

  if (( KEEP_ARTIFACTS == 0 )); then
    rmdir "${artifact_dir}" >/dev/null 2>&1 || true
  fi
}

collect_artifact_stats() {
  case "${MODE}" in
    sysdig_compress)
      collect_sysdig_compress_stats
      ;;
    nodrop_compress)
      collect_nodrop_compress_stats
      ;;
    *)
      ;;
  esac
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
      "${NODROP_BIN}" start "${NODROP_COUNT_LUA}"
      "${NODROP_BIN}" record none
      ;;

    nodrop_compress)
      log "Starting NoDrop + record compress"
      snapshot_nodrop_outputs_before
      "${NODROP_BIN}" start
      "${NODROP_BIN}" record compress
      ;;

    sysdig_count)
      if [[ -z "${SYSDIG_COUNT_CMD_TEMPLATE}" ]]; then
        echo "[ERR] SYSDIG_COUNT_CMD_TEMPLATE is empty." >&2
        exit 1
      fi
      local cpu
      cpu="${REDIS_CORES[0]}"
      local out="${RUN_DIR}/sysdig_count.out"
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
      cpu="${REDIS_CORES[0]}"
      local out="${RUN_DIR}/sysdig_trace.scap.gz"
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
        pid=$(cat "${MONITOR_PID_FILE}" | head -n 1)
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
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
try:
    txt = open(path, "r", encoding="utf-8", errors="ignore").read().strip()
except Exception:
    print("0")
    sys.exit(0)

# typical: "GET","123456.78"
m = re.search(r'"[^"]+"\s*,\s*"([^"]+)"', txt)
if not m:
    print("0")
    sys.exit(0)

try:
    print(float(m.group(1)))
except Exception:
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
CURRENT_RUN_ID=0

do_single_run() {
  local run_id="$1"
  CURRENT_RUN_ID="${run_id}"

  setup_run_dirs "${MODE}" "${run_id}"

  log "=============================="
  log "Run ${run_id}/${RUNS}  config=${CONFIG}  mode=${MODE}"
  log "Run dir: ${RUN_DIR}"
  log "=============================="

  start_redis_instances
  start_monitor

  local total_rps
  total_rps=$(run_benchmarks_and_collect_total)

  stop_monitor
  stop_redis_instances

  collect_artifact_stats

  local per_inst_mem_mb=$((TOTAL_MEM_MB / INSTANCE_NR))

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date +'%F %T')" "${CONFIG}" "${MODE}" "${run_id}" \
    "${INSTANCE_NR}" "${TOTAL_MEM_MB}" "${per_inst_mem_mb}" "${total_rps}" \
    "${ARTIFACT_FILE_COUNT}" "${TOTAL_EVENT_COUNT}" "${TOTAL_COMPRESSED_BYTES}" "${TOTAL_UNCOMPRESSED_BYTES}" \
    >> "${RESULT_CSV}"

  log "Run ${run_id} total throughput = ${total_rps} req/s"
  if [[ "${MODE}" == "sysdig_compress" || "${MODE}" == "nodrop_compress" ]]; then
    log "Run ${run_id} artifacts: files=${ARTIFACT_FILE_COUNT}, events=${TOTAL_EVENT_COUNT}, compressed=${TOTAL_COMPRESSED_BYTES}, uncompressed=${TOTAL_UNCOMPRESSED_BYTES}"
  fi
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
log "Config=${CONFIG} Mode=${REQUESTED_MODE} Runs=${RUNS} KeepArtifacts=${KEEP_ARTIFACTS}"
log "Redis cores: $(join_by_comma "${REDIS_CORES[@]}")"
log "Bench cores: $(join_by_comma "${BENCH_CORES[@]}")"
log "Instances=${INSTANCE_NR}, TotalMem=${TOTAL_MEM_MB}MB"
log "Summary CSV: ${RESULT_CSV}"
log "Artifact CSV: ${ARTIFACT_CSV}"

if [[ "${REQUESTED_MODE}" == "all" ]]; then
  for m in baseline nodrop_count nodrop_compress sysdig_count sysdig_compress; do
    run_mode "${m}"
  done
else
  run_mode "${REQUESTED_MODE}"
fi

log "Done. Summary CSV: ${RESULT_CSV}"
log "Done. Artifact CSV: ${ARTIFACT_CSV}"