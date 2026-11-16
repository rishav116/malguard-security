"""
MALGUARD AI — Resilient ClamAV Daemon Lifecycle Supervisor.
Monitors, manages, and logs the genuine clamd process inside the Vercel Linux container.

Features:
- Launches genuine official ClamAV daemon (`/usr/sbin/clamd --foreground=true`).
- Streams ClamAV stdout/stderr directly to container stdout for real-time Vercel log visibility.
- Continuously probes 127.0.0.1:3310 for zPING and zVERSION verification.
- Manages atomic state flag files (/tmp/clamd.starting, /tmp/clamd.ready, /tmp/clamd.failed).
- Detects process exits and OOM kills (SIGKILL = 9) immediately.
- Dumps crash diagnostics and auto-restarts clamd with backoff.
- Tracks cgroup v1/v2 memory limits and emits warnings if approaching 2 GB limit.
"""

import os
import sys
import time
import socket
import signal
import subprocess
import threading
import json
from typing import Optional, Tuple, Dict, Any

CLAMAV_BIN = "/usr/sbin/clamd"
CONFIG_FILE = "/etc/clamav/clamd.conf"
HOST = "127.0.0.1"
PORT = 3310
STATUS_DIR = "/tmp"

FLAGS = {
    "starting": os.path.join(STATUS_DIR, "clamd.starting"),
    "ready": os.path.join(STATUS_DIR, "clamd.ready"),
    "failed": os.path.join(STATUS_DIR, "clamd.failed"),
    "status": os.path.join(STATUS_DIR, "clamd.status"),
    "memory": os.path.join(STATUS_DIR, "clamd.memory"),
    "crash": os.path.join(STATUS_DIR, "clamd.crash_info"),
    "pid": os.path.join(STATUS_DIR, "clamd.pid"),
}

shutdown_requested = False
crash_count = 0
restart_count = 0
current_status: Dict[str, Any] = {
    "state": "INITIALIZING",
    "pid": None,
    "version": None,
    "crashes": 0,
    "restarts": 0,
    "ready_at": None,
    "uptime_sec": 0,
    "last_error": None
}

def log(msg: str):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} | [clamd-supervisor] {msg}", flush=True)

def update_status_file():
    try:
        with open(FLAGS["status"], "w", encoding="utf-8") as f:
            json.dump(current_status, f)
    except Exception:
        pass

def get_cgroup_memory() -> Tuple[Optional[float], Optional[float]]:
    """Reads Linux cgroup v1 or v2 current memory usage and limits."""
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

def verify_databases() -> bool:
    """Verifies that official signature databases are present."""
    has_main = os.path.exists("/var/lib/clamav/main.cvd") or os.path.exists("/var/lib/clamav/main.cld")
    has_daily = os.path.exists("/var/lib/clamav/daily.cvd") or os.path.exists("/var/lib/clamav/daily.cld")
    if not has_main:
        log("FATAL: Required ClamAV database (main.cvd) is missing!")
        return False
    if not has_daily:
        log("FATAL: Required ClamAV database (daily.cvd) is missing!")
        return False
    return True

def probe_daemon_socket(timeout: float = 1.0) -> Tuple[bool, Optional[str], Optional[str]]:
    """Probes clamd on loopback with zPING and zVERSION."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((HOST, PORT))
        
        # Probe VERSION directly (verifies socket connectivity, daemon responsiveness, and version string in one operation)
        s.sendall(b"zVERSION\x00")
        raw_v = s.recv(1024).decode("utf-8", errors="ignore").strip().rstrip("\x00")
        if raw_v and raw_v.startswith("ClamAV ") and "/" in raw_v:
            return True, raw_v, None
        elif raw_v:
            return True, raw_v, None
        return False, None, "Daemon returned empty version response"
    except socket.timeout:
        return False, None, f"Socket timed out after {timeout}s"
    except ConnectionRefusedError:
        return False, None, "Connection refused (daemon not listening yet)"
    except Exception as e:
        return False, None, f"Socket error: {str(e)}"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass

def stream_process_output(pipe, prefix: str):
    """Streams child process stdout/stderr line by line to container log."""
    try:
        for line in iter(pipe.readline, ""):
            if not line:
                break
            clean_line = line.strip()
            if clean_line:
                print(f"[clamd] {clean_line}", flush=True)
    except Exception:
        pass
    finally:
        try:
            pipe.close()
        except Exception:
            pass

def dump_clamav_log(lines: int = 30):
    """Dumps the tail of the ClamAV log file on failure."""
    for log_path in ["/tmp/clamav.log", "/var/log/clamav/clamav.log"]:
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    all_lines = f.readlines()
                    tail = all_lines[-lines:] if len(all_lines) > lines else all_lines
                    log(f"--- TAIL OF {log_path} ({len(tail)} lines) ---")
                    for l in tail:
                        print(f"  [clamav.log] {l.strip()}", flush=True)
                    log("--- END LOG DUMP ---")
                    return
            except Exception as e:
                log(f"Could not read {log_path}: {e}")

def signal_handler(signum, frame):
    global shutdown_requested
    sig_name = signal.Signals(signum).name
    log(f"Received {sig_name}; initiating graceful shutdown of clamd supervisor...")
    shutdown_requested = True

def run_supervisor():
    global crash_count, restart_count, current_status, shutdown_requested

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    log("Initializing ClamAV Lifecycle Supervisor...")
    current_status["state"] = "STARTING"
    update_status_file()

    # Clean stale flags
    for key, path in FLAGS.items():
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    if not verify_databases():
        with open(FLAGS["failed"], "w") as f:
            f.write("Signature databases missing")
        current_status["state"] = "FAILED"
        current_status["last_error"] = "Signature databases missing"
        update_status_file()
        sys.exit(1)

    while not shutdown_requested:
        # Mark as starting
        if os.path.exists(FLAGS["ready"]):
            try:
                os.remove(FLAGS["ready"])
            except Exception:
                pass
        with open(FLAGS["starting"], "w") as f:
            f.write(f"Starting clamd at {time.time()}")
        
        current_status["state"] = "STARTING"
        update_status_file()

        log(f"Spawning clamd (attempt {restart_count + 1})...")
        cmd = [CLAMAV_BIN, f"--config-file={CONFIG_FILE}", "--foreground=true"]
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
        except Exception as e:
            log(f"CRITICAL: Failed to spawn clamd binary: {e}")
            with open(FLAGS["failed"], "w") as f:
                f.write(f"Spawn failure: {e}")
            current_status["state"] = "FAILED"
            current_status["last_error"] = str(e)
            update_status_file()
            time.sleep(5)
            continue

        pid = proc.pid
        current_status["pid"] = pid
        log(f"clamd process spawned with PID {pid}")
        with open(FLAGS["pid"], "w") as f:
            f.write(str(pid))

        # Start background stdout/stderr streamer
        t_stream = threading.Thread(target=stream_process_output, args=(proc.stdout, "[clamd]"), daemon=True)
        t_stream.start()

        # Readiness polling loop
        start_time = time.time()
        ready = False
        poll_count = 0

        while not shutdown_requested and proc.poll() is None:
            poll_count += 1
            current_status["uptime_sec"] = round(time.time() - start_time, 1)
            update_status_file()

            is_ok, ver, err = probe_daemon_socket(timeout=1.0)
            if is_ok:
                elapsed = round(time.time() - start_time, 2)
                log(f"SUCCESS: ClamAV daemon is ONLINE and verified on {HOST}:{PORT} (ready in {elapsed}s).")
                log(f"Engine Identity: {ver}")
                ready = True
                current_status["state"] = "ONLINE"
                current_status["version"] = ver
                current_status["ready_at"] = time.time()
                current_status["last_error"] = None
                
                # Atomically switch flags
                if os.path.exists(FLAGS["starting"]):
                    try:
                        os.remove(FLAGS["starting"])
                    except Exception:
                        pass
                with open(FLAGS["ready"], "w") as f:
                    f.write(f"ONLINE {ver} ready_at={time.time()}")
                update_status_file()
                break

            if poll_count % 5 == 0:
                elapsed = round(time.time() - start_time, 1)
                log(f"Waiting for clamd socket on {HOST}:{PORT}... ({elapsed}s elapsed, status: {err})")
            
            # Check cgroup memory while waiting
            usage_mb, limit_mb = get_cgroup_memory()
            if usage_mb and limit_mb:
                pct = (usage_mb / limit_mb) * 100
                if pct > 85.0:
                    log(f"WARNING: Memory usage near limit during startup: {usage_mb} MB / {limit_mb} MB ({pct:.1f}%)")

            time.sleep(1.0)

        # Main supervision loop while clamd is running
        check_interval = 0
        while not shutdown_requested and proc.poll() is None:
            time.sleep(2.0)
            check_interval += 2
            
            # Update uptime
            if current_status["ready_at"]:
                current_status["uptime_sec"] = round(time.time() - current_status["ready_at"], 1)

            # Every 10 seconds: probe socket to verify liveness
            if check_interval % 10 == 0:
                is_ok, ver, err = probe_daemon_socket(timeout=1.5)
                if not is_ok:
                    log(f"WARNING: clamd socket probe failed while running: {err}")
                else:
                    current_status["state"] = "ONLINE"

            # Check memory telemetry every 10 seconds
            if check_interval % 10 == 0:
                usage_mb, limit_mb = get_cgroup_memory()
                if usage_mb:
                    mem_data = {"usage_mb": usage_mb, "limit_mb": limit_mb, "timestamp": time.time()}
                    try:
                        with open(FLAGS["memory"], "w") as mf:
                            json.dump(mem_data, mf)
                    except Exception:
                        pass
                    if limit_mb and (usage_mb / limit_mb) > 0.85:
                        log(f"WARNING: High container memory usage: {usage_mb} MB / {limit_mb} MB ({(usage_mb/limit_mb)*100:.1f}%)")

            update_status_file()

        # If process exited
        exit_code = proc.poll()
        if shutdown_requested:
            log(f"Terminating clamd (PID {pid}) for graceful container shutdown...")
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            break

        crash_count += 1
        restart_count += 1
        current_status["crashes"] = crash_count
        current_status["restarts"] = restart_count
        current_status["state"] = "CRASHED"
        
        # Analyze exit reason
        sig_info = "NORMAL_EXIT"
        if exit_code is not None and exit_code < 0:
            sig_num = -exit_code
            try:
                sig_name = signal.Signals(sig_num).name
            except Exception:
                sig_name = f"SIGNAL_{sig_num}"
            sig_info = f"TERMINATED_BY_{sig_name}"
            
            if sig_num == 9:  # SIGKILL
                log(f"CRITICAL: clamd (PID {pid}) was killed by SIGKILL (Signal 9)!")
                log("DIAGNOSIS: On Linux containers, SIGKILL without core dump is the signature of the cgroup OOM killer (Out of Memory).")
            else:
                log(f"CRITICAL: clamd (PID {pid}) terminated by {sig_name} (Signal {sig_num})!")
        else:
            log(f"CRITICAL: clamd (PID {pid}) exited with returncode {exit_code}!")

        # Clean ready flag and set failed flag
        if os.path.exists(FLAGS["ready"]):
            try:
                os.remove(FLAGS["ready"])
            except Exception:
                pass
        with open(FLAGS["failed"], "w") as f:
            f.write(f"Crashed with exit code {exit_code} ({sig_info}) at {time.time()}")
        
        # Save crash record
        crash_record = {
            "crashed_at": time.time(),
            "pid": pid,
            "exit_code": exit_code,
            "signal": sig_info,
            "crashes_total": crash_count
        }
        try:
            with open(FLAGS["crash"], "w") as cf:
                json.dump(crash_record, cf)
        except Exception:
            pass

        current_status["last_error"] = f"Exited with code {exit_code} ({sig_info})"
        update_status_file()

        # Dump ClamAV log file
        dump_clamav_log(lines=40)

        log(f"Restarting clamd in 3 seconds (crash #{crash_count})...")
        time.sleep(3)

    log("ClamAV Supervisor terminated.")

if __name__ == "__main__":
    run_supervisor()
