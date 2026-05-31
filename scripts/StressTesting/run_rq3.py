#!/usr/bin/python3
"""RQ3 Runtime Overhead Test - measures application performance overhead of NoDrop vs Sysdig.

Usage:
  python3 run_rq3.py --loop 10                          # full test
  python3 run_rq3.py --loop 1 --stress 0/10000           # quick: without SP only
  python3 run_rq3.py --loop 1 --apps openssl --dry-run   # print plan only
"""

import argparse
import csv
import math
import os
import re
import signal
import shlex
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from datetime import datetime

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Auto-detect project root from script location
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(_SCRIPT_DIR))  # scripts/StressTesting -> project root
BUILD_DIR = os.environ.get("NODROP_BUILD_DIR", os.path.join(PROJECT_ROOT, "build"))
CTRL_BIN = os.path.join(BUILD_DIR, "scripts", "ctrl", "ctrl")
STRESS_BIN = os.path.join(BUILD_DIR, "scripts", "StressTesting", "stress")
NODROP_KO = os.path.join(BUILD_DIR, "kmodule", "src", "nodrop.ko")
BENCHMARK_DIR = os.path.join(PROJECT_ROOT, "benchmark")

REDIS_SERVER_LOCAL = os.path.join(BENCHMARK_DIR, "redis", "redis_", "src", "redis-server")
REDIS_BENCHMARK_LOCAL = os.path.join(BENCHMARK_DIR, "redis", "redis_", "src", "redis-benchmark")
REDIS_CLI_LOCAL = os.path.join(BENCHMARK_DIR, "redis", "redis_", "src", "redis-cli")
NGINX_LOCAL = os.path.join(BENCHMARK_DIR, "nginx", "nginx_", "sbin", "nginx")
WRK_LOCAL = os.path.join(BENCHMARK_DIR, "nginx", "wrk_", "wrk")

REDIS_SERVER_BIN = REDIS_SERVER_LOCAL
REDIS_BENCHMARK_BIN = REDIS_BENCHMARK_LOCAL
REDIS_CLI_BIN = REDIS_CLI_LOCAL
NGINX_BIN = NGINX_LOCAL
WRK_BIN = WRK_LOCAL

# ---------------------------------------------------------------------------
# Config definitions
# ---------------------------------------------------------------------------
ALL_APPS = ["openssl", "7zip", "postmark", "redis", "nginx"]
ALL_TOOLS = ["baseline", "nodrop", "sysdig"]
# Fixed hardware configurations matching the original RQ3 scripts.
# TOTAL_CPU/CPULINE come from benchmark/test_openssl.py and
# benchmark/test_nginx_cg.py comments; Redis core roles come from
# benchmark/test_redis_single.py comments.
# Default --configs C1 on small hosts; add C2/C3/C4 on larger machines.
CPU_CONFIGS = {
    "C1": {
        "nr": 1,
        "bench_cores": "0",
        "multi": 1,
        "redis_server_cores": ["0"],
        "redis_client_cores": ["1"],
        "nginx_server_cores": "0",
        "nginx_client_cores": "1",
        "nginx_threads": 2,
    },
    "C2": {
        "nr": 4,
        "bench_cores": "0-3",
        "multi": 4,
        "redis_server_cores": ["0", "1", "2", "3"],
        "redis_client_cores": ["4", "5", "6", "7"],
        "nginx_server_cores": "0-7",
        "nginx_client_cores": "4-5",
        "nginx_threads": 8,
    },
    "C3": {
        "nr": 16,
        "bench_cores": "0-15",
        "multi": 16,
        "redis_server_cores": [str(i) for i in range(8)],
        "redis_client_cores": [str(i) for i in range(16, 24)],
        "nginx_server_cores": "0-7",
        "nginx_client_cores": "16-23",
        "nginx_threads": 16,
    },
    "C4": {
        "nr": 32,
        "bench_cores": "0-31",
        "multi": 32,
        "redis_server_cores": [str(i) for i in range(12)],
        "redis_client_cores": [str(i) for i in range(22, 34)],
        "nginx_server_cores": "0-7",
        "nginx_client_cores": "32-39",
        "nginx_threads": 32,
    },
}
# Stress intensity: paper Tables 4a/4b report two categories:
#   n=0  -> "without super producer" (Table 4a)
#   n>0  -> "with super producer"    (Table 4b)
# Code tests multiple n values; published tables collapse into without/with.
DEFAULT_STRESS_CFGS = [(0, 10000), (10, 10000)]


# ---------------------------------------------------------------------------
# UID matching the paper's methodology (non-root user for benchmarks)
# ---------------------------------------------------------------------------
BENCH_UID = 1000
BENCH_GID = 1000
REDIS_PORT_MIN = 16400
REDIS_PORT_MAX = 39999


def _drop_privs():
    """pre-exec hook: drop root privileges for stress/benchmark child processes."""
    os.setgroups([])
    os.setgid(BENCH_GID)
    os.setuid(BENCH_UID)


def run(cmd, **kwargs):
    """Run a command as root, return CompletedProcess. Quiet by default."""
    kwargs.setdefault("stdout", subprocess.DEVNULL)
    kwargs.setdefault("stderr", subprocess.DEVNULL)
    kwargs.setdefault("shell", True)
    return subprocess.run(cmd, **kwargs)


def run_output(cmd, **kwargs):
    """Run a command as root, return stdout string."""
    kwargs.setdefault("stderr", subprocess.DEVNULL)
    kwargs.setdefault("shell", True)
    # Unset proxy env vars so localhost connections go direct
    env = {**os.environ, "http_proxy": "", "https_proxy": "",
           "HTTP_PROXY": "", "HTTPS_PROXY": "", "NO_PROXY": "*"}
    kwargs.setdefault("env", env)
    return subprocess.check_output(cmd, **kwargs).decode("utf-8", errors="replace").strip()


def run_as_user(cmd, **kwargs):
    """Run a command as uid 1000, return CompletedProcess."""
    kwargs.setdefault("stdout", subprocess.DEVNULL)
    kwargs.setdefault("stderr", subprocess.DEVNULL)
    kwargs.setdefault("shell", True)
    kwargs["preexec_fn"] = _drop_privs
    return subprocess.run(cmd, **kwargs)


def run_output_as_user(cmd, **kwargs):
    """Run a command as uid 1000, return stdout string."""
    kwargs.setdefault("stderr", subprocess.DEVNULL)
    kwargs.setdefault("shell", True)
    kwargs["preexec_fn"] = _drop_privs
    env = {**os.environ, "http_proxy": "", "https_proxy": "",
           "HTTP_PROXY": "", "HTTPS_PROXY": "", "NO_PROXY": "*"}
    kwargs.setdefault("env", env)
    return subprocess.check_output(cmd, **kwargs).decode("utf-8", errors="replace").strip()


def _proc_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _pids_matching(match_func):
    pids = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == os.getpid():
            continue
        cmdline = _proc_cmdline(pid)
        if cmdline and match_func(cmdline):
            pids.append(pid)
    return pids


def _kill_pids(pids, sig):
    for pid in pids:
        try:
            os.kill(pid, sig)
        except OSError:
            pass


def kill_matching(match_func):
    """Kill only processes whose command line belongs to this RQ3 script."""
    pids = _pids_matching(match_func)
    if not pids:
        return
    _kill_pids(pids, signal.SIGTERM)
    time.sleep(1.5)
    remaining = [pid for pid in pids if os.path.exists(f"/proc/{pid}")]
    _kill_pids(remaining, signal.SIGKILL)


def _is_rq3_stress(cmdline):
    return STRESS_BIN in cmdline


def _is_rq3_wrk(cmdline):
    return "wrk" in cmdline and "http://127.0.0.1:18" in cmdline


def _is_rq3_sysdig(cmdline):
    return "sysdig" in cmdline and "/tmp/rq3_sysdig.scap" in cmdline


def _redis_ports_in_cmdline(cmdline):
    ports = []
    for match in re.findall(r":(\d{2,5})\b|--port\s+(\d{2,5})\b", cmdline):
        port_s = match[0] or match[1]
        try:
            ports.append(int(port_s))
        except ValueError:
            pass
    return ports


def _is_rq3_redis(cmdline):
    if "redis-server" not in cmdline:
        return False
    return any(REDIS_PORT_MIN <= port <= REDIS_PORT_MAX
               for port in _redis_ports_in_cmdline(cmdline))


def _is_rq3_nginx(cmdline):
    return ("nginx" in cmdline and "/tmp/" in cmdline
            and "nginx.conf" in cmdline and "daemon on" in cmdline)


# ---------------------------------------------------------------------------
# Tool classes  (Baseline / NoDrop / Sysdig)
# ---------------------------------------------------------------------------
class Tool(ABC):
    @abstractmethod
    def start(self, bench_cores: str): ...
    @abstractmethod
    def stop(self): ...
    @abstractmethod
    def get_stats(self) -> tuple: ...  # (n_evts, drop_evts, drop_unsolved)


class Baseline(Tool):
    def start(self, bench_cores):
        pass

    def stop(self):
        pass

    def get_stats(self):
        return (0, 0, 0)


class NoDropTool(Tool):
    def __init__(self):
        self._stats = (0, 0, 0)
        self._recording = False

    def start(self, bench_cores):
        run("rmmod nodrop 2>/dev/null || true")
        p = run(f"insmod {NODROP_KO}")
        if p.returncode != 0:
            raise RuntimeError("failed to load nodrop module")
        time.sleep(1)
        run(f"{CTRL_BIN} clean")
        run(f"{CTRL_BIN} clear-stat")
        run(f"{CTRL_BIN} start")
        run(f"{CTRL_BIN} record none")
        self._recording = True

    def stop(self):
        self.stop_recording()
        self._stats = self._read_stats()

        # NoDrop does not drop events, so process-local monitor work can remain
        # after the benchmark returns. Give it a bounded quiesce window before
        # unloading the module; never force-unload a busy NoDrop module.
        self._wait_quiescent()
        self._unload_module()

    def stop_recording(self):
        if not self._recording:
            return
        run(f"{CTRL_BIN} stop")
        self._recording = False

    def _read_stats(self):
        out = run_output(f"{CTRL_BIN} stat")
        parts = out.strip().split("\n")[-1].split()
        # Format: n_evts\tdrop_evts\tdrop_unsolved
        n_evts = int(parts[0]) if len(parts) >= 1 else 0
        drop_evts = int(parts[1]) if len(parts) >= 2 else 0
        drop_unsolved = int(parts[2]) if len(parts) >= 3 else 0
        return (n_evts, drop_evts, drop_unsolved)

    def _read_buffer_count(self):
        out = run_output(f"{CTRL_BIN} count")
        values = {}
        for part in out.split(","):
            if "=" not in part:
                continue
            key, value = part.strip().split("=", 1)
            values[key] = int(value)
        for key in ("event_count", "unflushed_count", "unflushed_len"):
            if key not in values:
                raise RuntimeError(f"missing {key} in ctrl count output: {out!r}")
        return values

    def _wait_quiescent(self):
        timeout_s = int(os.environ.get("NODROP_DRAIN_TIMEOUT", "120"))
        report_interval_s = int(os.environ.get("NODROP_DRAIN_LOG_INTERVAL", "60"))
        stall_timeout_s = int(os.environ.get("NODROP_DRAIN_STALL_TIMEOUT", "120"))
        count_error_limit = int(os.environ.get("NODROP_COUNT_ERROR_LIMIT", "3"))
        start = time.time()
        deadline = time.time() + timeout_s
        last_report = start
        last_change = start
        last_seen = None
        count_errors = 0
        while time.time() < deadline:
            try:
                counts = self._read_buffer_count()
                count_errors = 0
                unflushed = counts["unflushed_count"]
                unflushed_len = counts["unflushed_len"]
                current = (unflushed, unflushed_len)
                if current != last_seen:
                    last_seen = current
                    last_change = time.time()
                if unflushed == 0:
                    return True
                now = time.time()
                stalled_for = int(now - last_change)
                if stall_timeout_s > 0 and now - last_change >= stall_timeout_s:
                    print(f"  WARNING: nodrop drain stalled ({unflushed} unflushed, "
                          f"{unflushed_len} bytes, no progress for {stalled_for}s)",
                          flush=True)
                    return False
                if report_interval_s > 0 and now - last_report >= report_interval_s:
                    remaining = int(deadline - now)
                    print(f"  Waiting for nodrop quiesce ({unflushed} unflushed, "
                          f"{unflushed_len} bytes, stalled {stalled_for}s, "
                          f"timeout in {remaining}s)...", flush=True)
                    last_report = now
                time.sleep(2)
            except Exception as exc:
                count_errors += 1
                if count_errors >= count_error_limit:
                    print(f"  WARNING: failed to read nodrop drain state "
                          f"{count_errors} times: {exc}", flush=True)
                    return False
                time.sleep(2)
        if last_seen is None:
            print("  WARNING: nodrop drain state was never observed before timeout")
        else:
            unflushed, unflushed_len = last_seen
            print(f"  WARNING: nodrop did not fully quiesce before unload attempt "
                  f"({unflushed} unflushed, {unflushed_len} bytes, "
                  f"last progress {int(time.time() - last_change)}s ago)")
        return False

    def _unload_module(self):
        timeout_s = int(os.environ.get("NODROP_RMMOD_TIMEOUT", "120"))
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            p = run("rmmod nodrop")
            if p.returncode == 0:
                return
            time.sleep(2)
        print("  WARNING: rmmod nodrop still failed; leaving module loaded for cleanup")

    def get_stats(self):
        return self._stats


class SysdigTool(Tool):
    def __init__(self):
        self._pid = None
        self._stats = (0, 0, 0)

    def start(self, bench_cores):
        run("modprobe scap")
        run("dmesg -c")
        time.sleep(1)
        p = subprocess.Popen(
            f"exec taskset -c {bench_cores} sysdig -s 4096 -w /tmp/rq3_sysdig.scap",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self._pid = p.pid
        time.sleep(2)

    def stop(self):
        if self._pid:
            try:
                os.kill(self._pid, signal.SIGINT)
            except OSError:
                pass
        time.sleep(3)
        self._stats = self._read_stats()
        kill_matching(_is_rq3_sysdig)
        time.sleep(1)
        run("rmmod scap")
        time.sleep(1)
        run("rm -f /tmp/rq3_sysdig.scap")

    def _read_stats(self):
        out = run_output("dmesg -c")
        n_evts, drop_evts = 0, 0
        for line in out.split("\n"):
            if "total_evts" in line:
                nums = [int(x) for x in re.findall(r"\d+", line)]
                if len(nums) >= 2:
                    n_evts = nums[-2]
                    drop_evts = nums[-1]
        # Truncate scap file to prevent disk from filling
        run("truncate -s 0 /tmp/rq3_sysdig.scap 2>/dev/null || true")
        return (n_evts, drop_evts, 0)

    def get_stats(self):
        return self._stats


TOOL_MAP = {
    "baseline": Baseline,
    "nodrop": NoDropTool,
    "sysdig": SysdigTool,
}


# ---------------------------------------------------------------------------
# Benchmark classes  (5 RQ3 applications kept in this script)
# ---------------------------------------------------------------------------
class Benchmark(ABC):
    metric: str = "unknown"

    @abstractmethod
    def run(self, cfg: dict, duration: int) -> float: ...


class OpenSSL(Benchmark):
    metric = "us/signature"

    def run(self, cfg, duration):
        out = run_output_as_user(
            f"taskset -c {cfg['bench_cores']} openssl speed -multi {cfg['multi']} "
            f"-seconds {duration} rsa4096",
            stderr=subprocess.DEVNULL,
        )
        for line in out.split("\n"):
            if "rsa 4096 bits" in line:
                # Paper: lines[-2].split()[3][:-1] * 1e6 -> us per signature
                parts = line.split()
                sign_time_s = float(parts[3].rstrip("s"))
                return sign_time_s * 1e6
        return 0.0


class Zip7(Benchmark):
    metric = "MIPS"

    def run(self, cfg, duration):
        out = run_output_as_user(
            f"taskset -c {cfg['bench_cores']} 7z b", stderr=subprocess.DEVNULL)
        for line in out.split("\n"):
            if line.startswith("Tot:"):
                # Paper: int(lines[-2].strip().split()[-1]) -> MIPS (last column)
                return float(line.split()[-1])
        return 0.0


class Postmark(Benchmark):
    metric = "ms"

    def run(self, cfg, duration):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            os.chown(d, BENCH_UID, BENCH_GID)
            cfg = os.path.join(d, "pmrc")
            with open(cfg, "w") as f:
                f.write("set transactions 10000\nset size 5120 524288\n"
                        "set number 500\nshow\nrun\nquit\n")
            os.chown(cfg, BENCH_UID, BENCH_GID)
            t0 = time.time()
            run_as_user(f"cd {d} && postmark {cfg}")
            elapsed_ms = (time.time() - t0) * 1000
            return elapsed_ms


class RedisBench(Benchmark):
    metric = "req/s"
    PORT_BASE = REDIS_PORT_MIN
    REQUESTS = 1000000

    def run(self, cfg, duration):
        # Original benchmark/test_redis_single.py: one Redis server per
        # configured server core and one redis-benchmark per server.
        server_cores = cfg["redis_server_cores"]
        client_cores = cfg["redis_client_cores"]
        base_port = RedisBench.PORT_BASE
        RedisBench.PORT_BASE += len(server_cores) + 10  # avoid port clashes

        # Start all servers
        procs = []
        for i, core in enumerate(server_cores):
            port = base_port + i
            run_as_user(
                f"taskset -c {core} {REDIS_SERVER_BIN} --port {port} "
                f"--daemonize yes --save \"\" --appendonly no --dir /tmp")
        time.sleep(1)

        client_procs = []
        # Run all clients in parallel, sum the results
        try:
            total_reqs = 0.0
            for i, core in enumerate(client_cores[:len(server_cores)]):
                port = base_port + i
                p = subprocess.Popen(
                    f"exec taskset -c {core} {REDIS_BENCHMARK_BIN} -h 127.0.0.1 -p {port} "
                    f"-q -t get --csv -d 0 -c 200 -n {RedisBench.REQUESTS}",
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    preexec_fn=_drop_privs,
                )
                client_procs.append(p)

            for p in client_procs:
                out, _ = p.communicate(timeout=600)
                for line in out.decode("utf-8", errors="replace").split("\n"):
                    if line.startswith('"GET"'):
                        total_reqs += float(line.split(",")[1].strip('"'))
            return total_reqs
        finally:
            for p in client_procs:
                if p.poll() is None:
                    try:
                        p.terminate()
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        p.kill()
                    except OSError:
                        pass
            for i in range(len(server_cores)):
                port = base_port + i
                run_as_user(f"{REDIS_CLI_BIN} -p {port} shutdown nosave")


class NginxBench(Benchmark):
    metric = "us/req"
    PORT_START = 18050
    _next_port = PORT_START

    def run(self, cfg, duration):
        import tempfile
        port = NginxBench._next_port
        NginxBench._next_port += 1

        with tempfile.TemporaryDirectory() as d:
            os.chown(d, BENCH_UID, BENCH_GID)
            os.chmod(d, 0o755)
            html = os.path.join(d, "test.html")
            with open(html, "w") as f:
                f.write("OK")
            os.chown(html, BENCH_UID, BENCH_GID)
            os.chmod(html, 0o644)
            temp_dirs = {}
            for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
                path = os.path.join(d, name)
                os.mkdir(path)
                os.chown(path, BENCH_UID, BENCH_GID)
                temp_dirs[name] = path

            conf = os.path.join(d, "nginx.conf")
            with open(conf, "w") as f:
                f.write(f"error_log /dev/null;\npid {d}/nginx.pid;\n"
                        f"events {{ worker_connections 4096; }}\n"
                        f"http {{ access_log off; "
                        f"client_body_temp_path {temp_dirs['client_body']}; "
                        f"proxy_temp_path {temp_dirs['proxy']}; "
                        f"fastcgi_temp_path {temp_dirs['fastcgi']}; "
                        f"uwsgi_temp_path {temp_dirs['uwsgi']}; "
                        f"scgi_temp_path {temp_dirs['scgi']}; "
                        f"server {{ listen {port}; location / {{ root {d}; }} }} }}\n")

            p = run_as_user(f"taskset -c {cfg['nginx_server_cores']} {NGINX_BIN} -c {conf} -g 'daemon on;'")
            if p.returncode != 0:
                raise RuntimeError("nginx failed to start")
            time.sleep(1)

            try:
                # Original benchmark/test_nginx_cg.py:
                # wrk -t NRCPUS -c 100 -d DURATION --timeout DURATION.
                # Retry up to 2 times if nginx doesn't respond (can happen under load)
                rps = 0.0
                for attempt in range(2):
                    out = run_output_as_user(
                        f"taskset -c {cfg['nginx_client_cores']} {WRK_BIN} "
                        f"-t {cfg['nginx_threads']} -c 100 -d {duration}s "
                        f"--timeout {duration} http://127.0.0.1:{port}/test.html",
                    )
                    for line in out.split("\n"):
                        if "Requests/sec:" in line:
                            rps = float(line.split(":")[1].strip())
                    if rps > 0:
                        break
                    if attempt == 0:
                        time.sleep(3)
                return 1e6 / rps if rps > 0 else 0.0
            finally:
                run(f"{NGINX_BIN} -c {conf} -s quit")


APP_MAP = {
    "openssl": OpenSSL,
    "7zip": Zip7,
    "postmark": Postmark,
    "redis": RedisBench,
    "nginx": NginxBench,
}

APP_DURATIONS = {
    "openssl": 20, "7zip": 10, "postmark": 10,
    "redis": 10, "nginx": 20,
}


# ---------------------------------------------------------------------------
# Stress producer
# ---------------------------------------------------------------------------
class StressProducer:
    def __init__(self, stress_bin=STRESS_BIN):
        self._bin = stress_bin
        self._procs = []

    def start(self, n, m, nr_cores):
        if n == 0:
            return  # without super producer
        run(f"mkdir -p /tmp/count && chown {BENCH_UID}:{BENCH_GID} /tmp/count")
        for i in range(nr_cores):
            p = subprocess.Popen(
                f"exec taskset -c {i} {self._bin} {n} {m} {i}",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=_drop_privs,
            )
            self._procs.append(p)
        time.sleep(1)

    def stop(self):
        if not self._procs:
            return
        for p in self._procs:
            try:
                os.kill(p.pid, signal.SIGINT)
            except OSError:
                pass
        for p in self._procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    p.kill()
                except OSError:
                    pass
            except OSError:
                pass
        for p in self._procs:
            try:
                p.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            except OSError:
                pass
        self._procs = []
        time.sleep(1)
        run("rm -rf /tmp/count")


# ---------------------------------------------------------------------------
# Force cleanup (called before/after each tool section)
# ---------------------------------------------------------------------------
def cleanup_bench_processes():
    """Kill leftover benchmark/stress processes."""
    kill_matching(_is_rq3_stress)
    kill_matching(_is_rq3_wrk)
    kill_matching(_is_rq3_sysdig)
    kill_matching(_is_rq3_nginx)
    kill_matching(_is_rq3_redis)


def rq3_leftover_processes():
    matchers = (_is_rq3_stress, _is_rq3_wrk, _is_rq3_sysdig,
                _is_rq3_nginx, _is_rq3_redis)
    leftovers = []
    for pid in _pids_matching(lambda cmdline: any(m(cmdline) for m in matchers)):
        leftovers.append((pid, _proc_cmdline(pid)))
    return leftovers


def force_cleanup():
    """Kill all test processes and unload modules."""
    cleanup_bench_processes()
    run(f"{CTRL_BIN} stop 2>/dev/null || true")
    time.sleep(1)
    run("rmmod nodrop 2>/dev/null || true")
    run("rmmod scap 2>/dev/null || true")
    time.sleep(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_stress(spec):
    """Parse '0/10000,10/10000' into [(0,10000),(10,10000),...]"""
    cfgs = []
    for item in spec.split(","):
        item = item.strip()
        if "/" in item:
            n, m = item.split("/", 1)
            cfgs.append((int(n), int(m)))
    return cfgs


def _expand_core_spec(spec):
    cores = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            cores.extend(range(int(start), int(end) + 1))
        else:
            cores.append(int(part))
    return cores


def _config_core_set(cfg, apps):
    cores = []
    if any(app in apps for app in ("openssl", "7zip", "postmark")):
        cores.extend(_expand_core_spec(cfg["bench_cores"]))
    if "nginx" in apps:
        for key in ("nginx_server_cores", "nginx_client_cores"):
            cores.extend(_expand_core_spec(cfg[key]))
    if "redis" in apps:
        for key in ("redis_server_cores", "redis_client_cores"):
            for core in cfg[key]:
                cores.extend(_expand_core_spec(core))
    return set(cores)


def _config_required_cores(cfg, apps):
    cores = _config_core_set(cfg, apps)
    return max(cores) + 1 if cores else 0


def _command_available(cmd):
    if os.path.isabs(cmd) or os.sep in cmd:
        return os.path.exists(cmd)
    return any(os.path.isfile(os.path.join(p, cmd))
               for p in os.environ.get("PATH", "").split(":"))


def _command_available_for_bench_user(cmd):
    if not _command_available(cmd):
        return False
    if os.geteuid() != 0:
        return True
    if os.path.isabs(cmd) or os.sep in cmd:
        test_cmd = f"test -x {shlex.quote(cmd)}"
    else:
        test_cmd = f"command -v {shlex.quote(cmd)} >/dev/null 2>&1"
    try:
        return subprocess.run(
            test_cmd, shell=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, preexec_fn=_drop_privs,
        ).returncode == 0
    except Exception:
        return False


def _cpu_has_pkeys():
    try:
        with open("/proc/cpuinfo") as f:
            flags = set()
            for line in f:
                if line.startswith("flags"):
                    flags.update(line.split(":", 1)[1].split())
                    break
        return "pku" in flags and "ospke" in flags
    except OSError:
        return False


def _available_cpus():
    try:
        return set(os.sched_getaffinity(0))
    except AttributeError:
        return set(range(os.cpu_count() or 1))


def _format_core_range(cores):
    if not cores:
        return ""
    ordered = sorted(cores)
    ranges = []
    start = prev = ordered[0]
    for core in ordered[1:]:
        if core == prev + 1:
            prev = core
            continue
        ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
        start = prev = core
    ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
    return ",".join(ranges)


def _build_uses_pkeys():
    cache = os.path.join(BUILD_DIR, "CMakeCache.txt")
    try:
        with open(cache) as f:
            for line in f:
                if line.startswith("PKEY_SUPPORT:BOOL="):
                    return line.strip().endswith("ON")
    except OSError:
        pass
    monitor_flags = os.path.join(BUILD_DIR, "monitor", "CMakeFiles", "monitor.dir", "flags.make")
    try:
        with open(monitor_flags) as f:
            return "NOD_PKEY_SUPPORT" in f.read()
    except OSError:
        return False


def _check_deps(apps, tools):
    """Verify all required binaries exist. Returns list of missing items."""
    missing = []

    sys_tools = {"taskset": "apt install util-linux"}
    app_tools = {
        "taskset": "apt install util-linux",
        "openssl": "apt install openssl",
        "7z": "apt install p7zip-full",
        "postmark": "install postmark",
    }
    if "openssl" in apps:
        sys_tools["openssl"] = app_tools["openssl"]
    if "7zip" in apps:
        sys_tools["7z"] = app_tools["7z"]
    if "postmark" in apps:
        sys_tools["postmark"] = app_tools["postmark"]
    if "redis" in apps:
        sys_tools[REDIS_SERVER_BIN] = "run benchmark/redis/redis_install.sh"
        sys_tools[REDIS_BENCHMARK_BIN] = "run benchmark/redis/redis_install.sh"
        sys_tools[REDIS_CLI_BIN] = "run benchmark/redis/redis_install.sh"
    if "nginx" in apps:
        sys_tools[NGINX_BIN] = "run benchmark/nginx/nginx_install.sh"
        sys_tools[WRK_BIN] = "run benchmark/nginx/nginx_install.sh"

    for tool, pkg in sys_tools.items():
        if not _command_available_for_bench_user(tool):
            missing.append(f"{tool} ({pkg}; must be executable by uid {BENCH_UID})")

    # Project binaries
    for name, path in [("ctrl", CTRL_BIN), ("stress", STRESS_BIN), ("nodrop.ko", NODROP_KO)]:
        if not os.path.exists(path):
            missing.append(f"{path} - run 'make' in project root")

    if "nodrop" in tools and _build_uses_pkeys() and not _cpu_has_pkeys():
        missing.append(
            "NoDrop build has PKEY_SUPPORT=ON but this CPU lacks pku/ospke; "
            "reconfigure with 'cmake -S . -B build -DPKEY_SUPPORT=OFF' and rebuild"
        )

    # sysdig only needed if testing sysdig
    if "sysdig" in tools:
        if not _command_available("sysdig"):
            missing.append("sysdig (apt: sysdig)")
        # scap driver
        scap_paths = ["/lib/modules", "/usr/lib/modules"]
        scap_found = False
        for base in scap_paths:
            if os.path.exists(base):
                for root, _, files in os.walk(base):
                    if "scap.ko" in files:
                        scap_found = True
                        break
            if scap_found:
                break
        if not scap_found:
            missing.append("scap.ko - install sysdig package (apt: sysdig)")

    return missing


def main():
    parser = argparse.ArgumentParser(description="RQ3 Runtime Overhead Test")
    parser.add_argument("--apps", default="all",
                        help="Comma-separated app names (default: all)")
    parser.add_argument("--tools", default="all",
                        help="Comma-separated tool names (default: all)")
    parser.add_argument("--configs", default="C1",
                        help="Comma-separated CPU configs (default: C1)")
    parser.add_argument("--stress", default="0/10000,10/10000",
                        help="Stress n/m pairs comma-separated (default: 0/10000,10/10000)")
    parser.add_argument("--loop", type=int, default=10,
                        help="Iterations per combination (default: 10)")
    parser.add_argument("--duration", default="auto",
                        help="Test duration in seconds, or 'auto' (default: auto)")
    parser.add_argument("--redis-requests", type=int, default=1000000,
                        help="Redis requests per benchmark client (default: 1000000)")
    parser.add_argument("--output", default=f"{PROJECT_ROOT}/results/rq3",
                        help="Output directory")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print plan without executing")
    args = parser.parse_args()

    # Resolve selections
    apps = ALL_APPS if args.apps == "all" else [a.strip() for a in args.apps.split(",")]
    tools = ALL_TOOLS if args.tools == "all" else [t.strip() for t in args.tools.split(",")]
    configs = [c.strip() for c in args.configs.split(",")]
    stress_cfgs = parse_stress(args.stress)
    RedisBench.REQUESTS = args.redis_requests

    # Validate
    for a in apps:
        assert a in APP_MAP, f"Unknown app: {a}"
    for t in tools:
        assert t in TOOL_MAP, f"Unknown tool: {t}"
    for c in configs:
        assert c in CPU_CONFIGS, f"Unknown config: {c}"

    available_cpus = _available_cpus()
    unavailable = []
    for c in configs:
        needed = _config_core_set(CPU_CONFIGS[c], apps)
        missing_cores = needed - available_cpus
        if missing_cores:
            unavailable.append((c, needed, missing_cores))
    if unavailable:
        print("ERROR: CPU config exceeds this host or cpuset:")
        for c, needed, missing_cores in unavailable:
            print(f"  - {c} needs CPUs {_format_core_range(needed)}; "
                  f"missing {_format_core_range(missing_cores)}; "
                  f"available {_format_core_range(available_cpus)}")
        if not args.dry_run:
            return 1

    # Count total runs
    total_runs = len(tools) * len(configs) * len(stress_cfgs) * len(apps) * args.loop
    estimated_seconds = total_runs * 15  # rough estimate
    print(f"=== RQ3 Runtime Overhead Test ===")
    print(f"Apps:    {', '.join(apps)}")
    print(f"Tools:   {', '.join(tools)}")
    print(f"Configs: {', '.join(configs)}")
    print(f"Stress:  {stress_cfgs}")
    print(f"Loop:    {args.loop}")
    print(f"Redis requests: {RedisBench.REQUESTS}")
    print(f"Total runs: {total_runs}, est. time: ~{estimated_seconds // 60} min")
    print()

    # Check dependencies before running
    missing = _check_deps(apps, tools)
    if missing:
        print("ERROR: Missing dependencies:")
        for m in missing:
            print(f"  - {m}")
        print("\nProject-local installs: run benchmark/redis/redis_install.sh and benchmark/nginx/nginx_install.sh")
        print("System packages: apt install sysdig postmark p7zip-full openssl")
        if not args.dry_run:
            return 1

    if args.dry_run:
        print("=== Plan (dry-run) ===")
        for cfg_name in configs:
            cfg = CPU_CONFIGS[cfg_name]
            for tool_name in tools:
                for n, m in stress_cfgs:
                    sp_label = "without SP" if n == 0 else f"SP n={n}"
                    for app_name in apps:
                        print(f"  {cfg_name} {tool_name:8s} {sp_label:12s} {app_name:10s} x{args.loop}")
        print("\n(Dry run - no tests executed)")
        return 0

    # Setup output
    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(args.output, f"rq3_{ts}.csv")
    summary_path = os.path.join(args.output, f"rq3_summary_{ts}.txt")

    with open(csv_path, "w", newline="") as csv_f:
        writer = csv.writer(csv_f)
        writer.writerow(["config", "app", "tool", "stress_n", "stress_m",
                          "run", "value", "metric", "n_evts", "drop_evts",
                          "drop_unsolved"])

        for cfg_name in configs:
            cfg = CPU_CONFIGS[cfg_name]
            print(f"\n{'='*60}")
            print(f"Config: {cfg_name} ({cfg['nr']} cores)")
            print(f"{'='*60}")

            for tool_name in tools:
                print(f"\n--- Tool: {tool_name} ---")
                tool_cls = TOOL_MAP[tool_name]

                for n, m in stress_cfgs:
                    sp_label = "without SP" if n == 0 else f"SP n={n}/m={m}"

                    for app_name in apps:
                        app_cls = APP_MAP[app_name]
                        app_metric = app_cls.metric
                        duration = int(args.duration) if args.duration != "auto" else APP_DURATIONS[app_name]

                        print(f"  [{app_name}] {sp_label} ({args.loop}x{duration}s)...", end=" ", flush=True)

                        values = []
                        for run_idx in range(args.loop):
                            tool = tool_cls()
                            stress = StressProducer()
                            val = math.nan
                            n_evts = drop_evts = drop_unsolved = 0

                            force_cleanup()
                            time.sleep(1)
                            try:
                                app = app_cls()
                                tool.start(cfg["bench_cores"])
                                stress.start(n, m, cfg["nr"])
                                val = app.run(cfg, duration)
                            except Exception as exc:
                                print(f"\n    run {run_idx + 1} failed: {exc}", flush=True)
                            finally:
                                if isinstance(tool, NoDropTool):
                                    tool.stop_recording()
                                stress.stop()
                                if isinstance(tool, NoDropTool):
                                    cleanup_bench_processes()
                                    leftovers = rq3_leftover_processes()
                                    if leftovers:
                                        print("\n    WARNING: RQ3 processes still alive before nodrop drain:",
                                              flush=True)
                                        for pid, cmdline in leftovers[:5]:
                                            print(f"      pid={pid} {cmdline[:160]}",
                                                  flush=True)
                                try:
                                    tool.stop()
                                except Exception as exc:
                                    print(f"\n    tool stop failed: {exc}", flush=True)
                                try:
                                    n_evts, drop_evts, drop_unsolved = tool.get_stats()
                                except Exception:
                                    n_evts = drop_evts = drop_unsolved = 0
                                force_cleanup()

                            if _valid_value(val):
                                values.append(val)
                                out_val = round(val, 2)
                            else:
                                out_val = ""

                            writer.writerow([
                                cfg_name, app_name, tool_name, n, m,
                                run_idx + 1, out_val, app_metric,
                                n_evts, drop_evts, drop_unsolved,
                            ])
                            csv_f.flush()

                            if run_idx < args.loop - 1:
                                time.sleep(3)

                        if values:
                            avg = sum(values) / len(values)
                            writer.writerow([
                                cfg_name, app_name, tool_name, n, m,
                                "avg", round(avg, 2), app_metric, "", "", "",
                            ])
                            print(f"avg={avg:.2f} {app_metric}")
                        else:
                            writer.writerow([
                                cfg_name, app_name, tool_name, n, m,
                                "avg", "", app_metric, "", "", "",
                            ])
                            print("avg=NA")

    # --- Summary ---
    _write_summary(summary_path, csv_path, apps, tools, configs, stress_cfgs)
    print(f"\nDone. CSV: {csv_path}")
    print(f"Summary: {summary_path}")
    return 0


def _valid_value(value):
    return isinstance(value, (int, float)) and math.isfinite(value) and value > 0


def _metric_overhead(avg_val, base_val, metric):
    if not (_valid_value(avg_val) and _valid_value(base_val)):
        return ""
    if metric in ("MIPS", "req/s"):
        return f"{(base_val / avg_val - 1.0) * 100:+.1f}%"
    return f"{(avg_val / base_val - 1.0) * 100:+.1f}%"


def _write_summary(summary_path, csv_path, apps, tools, configs, stress_cfgs):
    """Compute per-group averages and overhead% vs baseline."""
    # Read back CSV into memory
    rows = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    with open(summary_path, "w") as f:
        f.write(f"RQ3 Summary - {datetime.now().isoformat()}\n")
        f.write(f"{'='*80}\n\n")

        # Build baseline lookup: (config, app, stress_n, stress_m) -> avg_value
        baseline = {}
        avg_lookup = {}
        for row in rows:
            if row["run"] == "avg" and row["value"]:
                key = (row["config"], row["app"], row["stress_n"], row["stress_m"])
                avg_lookup[(row["tool"],) + key] = float(row["value"])
                if row["tool"] == "baseline":
                    baseline[key] = float(row["value"])

        # Collect event counts per (tool, app, config, stress_n, stress_m)
        event_totals = {}
        for row in rows:
            if row["run"] not in ("avg", "") and row["n_evts"]:
                key = (row["tool"], row["app"], row["config"], row["stress_n"], row["stress_m"])
                n_evts = int(row["n_evts"]) if row["n_evts"] else 0
                drop_evts = int(row["drop_evts"]) if row["drop_evts"] else 0
                if key not in event_totals:
                    event_totals[key] = [0, 0]
                event_totals[key][0] += n_evts
                event_totals[key][1] += drop_evts

        # Print table per app
        for app_name in apps:
            for cfg_name in configs:
                f.write(f"\n### {app_name} | {cfg_name}\n")
                sep = f"{'Tool':<10s} {'SP':<14s} {'Avg':>12s} {'Metric':>8s} {'Overhead%':>10s} {'DropRate%':>10s}"
                f.write(sep + "\n")
                f.write("-" * len(sep) + "\n")

                for tool_name in tools:
                    for n, m in stress_cfgs:
                        avg_vals = [
                            float(row["value"])
                            for row in rows
                            if row["app"] == app_name and row["tool"] == tool_name
                            and row["config"] == cfg_name
                            and row["stress_n"] == str(n) and row["stress_m"] == str(m)
                            and row["run"] == "avg"
                            and row["value"]
                        ]
                        if not avg_vals:
                            continue
                        avg_val = avg_vals[0]
                        metric = next((row["metric"] for row in rows
                                       if row["app"] == app_name and row["run"] == "avg"), "?")

                        # overhead vs baseline
                        key = (cfg_name, app_name, str(n), str(m))
                        overhead = ""
                        if key in baseline and tool_name != "baseline":
                            base_val = baseline[key]
                            overhead = _metric_overhead(avg_val, base_val, metric)

                        # drop rate
                        drop_rate = ""
                        evt_key = (tool_name, app_name, cfg_name, str(n), str(m))
                        if evt_key in event_totals:
                            total, drops = event_totals[evt_key]
                            if total > 0:
                                drop_rate = f"{drops / total * 100:.2f}%"

                        sp = f"{n}/{m}" if int(n) > 0 else "without"
                        f.write(f"{tool_name:<10s} {sp:<14s} {avg_val:>12.2f} {metric:>8s} {overhead:>10s} {drop_rate:>10s}\n")

                for n, m in stress_cfgs:
                    nd_key = ("nodrop", cfg_name, app_name, str(n), str(m))
                    sd_key = ("sysdig", cfg_name, app_name, str(n), str(m))
                    if nd_key in avg_lookup and sd_key in avg_lookup:
                        metric = next((row["metric"] for row in rows
                                       if row["app"] == app_name and row["run"] == "avg"), "?")
                        diff = _metric_overhead(avg_lookup[nd_key], avg_lookup[sd_key], metric)
                        sp = f"{n}/{m}" if int(n) > 0 else "without"
                        f.write(f"{'DIFF':<10s} {sp:<14s} {'':>12s} {metric:>8s} {diff:>10s} {'':>10s}\n")


if __name__ == "__main__":
    sys.exit(main())
