import os
import sys
import time
import uuid
import socket
from typing import Dict, Any, Optional

BOOT_TIME = time.time()
INSTANCE_ID = f"inst-{str(uuid.uuid4())[:8]}"

def get_process_rss_mb(pid: int) -> Optional[float]:
    """Reads VmRSS from /proc/<pid>/status on Linux."""
    try:
        status_path = f"/proc/{pid}/status"
        if not os.path.exists(status_path):
            return None
        with open(status_path, "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        kb = float(parts[1])
                        return round(kb / 1024.0, 2)
    except Exception:
        pass
    return None

def get_cgroup_memory_mb() -> tuple[Optional[float], Optional[float]]:
    """Reads cgroup v1 or v2 current memory usage and limits."""
    usage_mb = None
    limit_mb = None
    try:
        # Cgroup v2
        if os.path.exists("/sys/fs/cgroup/memory.current"):
            with open("/sys/fs/cgroup/memory.current", "r") as f:
                usage_mb = round(int(f.read().strip()) / (1024 * 1024), 2)
            if os.path.exists("/sys/fs/cgroup/memory.max"):
                with open("/sys/fs/cgroup/memory.max", "r") as f:
                    val = f.read().strip()
                    if val != "max":
                        limit_mb = round(int(val) / (1024 * 1024), 2)
        # Cgroup v1 fallback
        elif os.path.exists("/sys/fs/cgroup/memory/memory.usage_in_bytes"):
            with open("/sys/fs/cgroup/memory/memory.usage_in_bytes", "r") as f:
                usage_mb = round(int(f.read().strip()) / (1024 * 1024), 2)
            if os.path.exists("/sys/fs/cgroup/memory/memory.limit_in_bytes"):
                with open("/sys/fs/cgroup/memory/memory.limit_in_bytes", "r") as f:
                    limit_mb = round(int(f.read().strip()) / (1024 * 1024), 2)
    except Exception:
        pass
    return usage_mb, limit_mb

def find_clamd_pid() -> Optional[int]:
    """Finds clamd PID from pidfile or process scan."""
    for path in ["/var/run/clamav/clamd.pid", "/run/clamav/clamd.pid", "/tmp/clamd.pid"]:
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    val = f.read().strip()
                    if val.isdigit():
                        pid = int(val)
                        try:
                            os.kill(pid, 0)
                            return pid
                        except OSError:
                            pass
        except Exception:
            pass
            
    # Fallback: scan /proc for clamd
    try:
        if os.path.isdir("/proc"):
            for d in os.listdir("/proc"):
                if d.isdigit():
                    cmdline_path = f"/proc/{d}/cmdline"
                    if os.path.exists(cmdline_path):
                        with open(cmdline_path, "rb") as f:
                            cmd = f.read().decode("utf-8", errors="ignore")
                            if "clamd" in cmd:
                                return int(d)
    except Exception:
        pass
    return None

def probe_clamd_socket(host: str = "127.0.0.1", port: int = 3310, timeout: float = 1.0) -> Dict[str, Any]:
    """Actively probes clamd on TCP socket with detailed timings."""
    diag = {
        "target": f"{host}:{port}",
        "connected": False,
        "connect_ms": None,
        "ping_ok": False,
        "ping_ms": None,
        "version": None,
        "error": None
    }
    t0 = time.perf_counter()
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        connect_ms = round((time.perf_counter() - t0) * 1000, 2)
        diag["connected"] = True
        diag["connect_ms"] = connect_ms

        # In clamd wire protocol, clamd answers a command and closes the connection.
        # Sending zVERSION probes responsiveness (PING equivalent) and retrieves version string in one operation.
        t_probe = time.perf_counter()
        s.sendall(b"zVERSION\x00")
        resp = s.recv(1024)
        diag["ping_ms"] = round((time.perf_counter() - t_probe) * 1000, 2)
        if resp:
            raw_v = resp.decode("utf-8", errors="ignore").strip().rstrip("\x00")
            diag["ping_ok"] = True
            diag["version"] = raw_v if raw_v else None
        else:
            diag["ping_ok"] = False
            diag["error"] = "clamd closed connection without version response"

    except socket.timeout:
        diag["error"] = f"Socket timed out after {timeout}s"
    except ConnectionRefusedError:
        diag["error"] = "Connection refused (daemon not listening yet or port closed)"
    except Exception as e:
        diag["error"] = f"Socket error: {str(e)}"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return diag

def get_system_diagnostics(clamav_host: str = "127.0.0.1", clamav_port: int = 3310) -> Dict[str, Any]:
    """Assembles comprehensive runtime diagnostics for health checks."""
    now = time.time()
    uptime_sec = round(now - BOOT_TIME, 2)
    fastapi_pid = os.getpid()
    clamd_pid = find_clamd_pid()
    clamd_alive = False
    if clamd_pid:
        try:
            os.kill(clamd_pid, 0)
            clamd_alive = True
        except OSError:
            clamd_alive = False

    fastapi_rss = get_process_rss_mb(fastapi_pid)
    clamd_rss = get_process_rss_mb(clamd_pid) if clamd_pid else None
    cgroup_usage, cgroup_limit = get_cgroup_memory_mb()

    socket_diag = probe_clamd_socket(host=clamav_host, port=clamav_port, timeout=0.5)

    # Flag files
    ready_flag = os.path.exists("/var/run/clamav/clamd.ready") or os.path.exists("/tmp/clamd.ready")
    starting_flag = os.path.exists("/var/run/clamav/clamd.starting") or os.path.exists("/tmp/clamd.starting")
    failed_flag = os.path.exists("/var/run/clamav/clamd.failed") or os.path.exists("/tmp/clamd.failed")
    crashed_flag = os.path.exists("/tmp/clamd.crash_info")

    supervisor_info = None
    if os.path.exists("/tmp/clamd.status"):
        try:
            with open("/tmp/clamd.status", "r", encoding="utf-8") as sf:
                supervisor_info = json.load(sf)
        except Exception:
            pass

    crash_info = None
    if os.path.exists("/tmp/clamd.crash_info"):
        try:
            with open("/tmp/clamd.crash_info", "r", encoding="utf-8") as cf:
                crash_info = json.load(cf)
        except Exception:
            pass

    return {
        "instance_id": INSTANCE_ID,
        "container_uptime_sec": uptime_sec,
        "is_cold_start": uptime_sec < 45.0,
        "pids": {
            "fastapi_pid": fastapi_pid,
            "clamd_pid": clamd_pid,
            "clamd_alive": clamd_alive,
        },
        "flags": {
            "ready": ready_flag,
            "starting": starting_flag,
            "failed": failed_flag,
            "crashed": crashed_flag,
        },
        "memory_mb": {
            "fastapi_rss": fastapi_rss,
            "clamd_rss": clamd_rss,
            "cgroup_current": cgroup_usage,
            "cgroup_limit": cgroup_limit,
        },
        "clamav_socket": socket_diag,
        "supervisor": supervisor_info,
        "last_crash": crash_info
    }
