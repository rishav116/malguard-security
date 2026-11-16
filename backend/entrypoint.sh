#!/bin/bash
set -e

echo "=========================================================="
echo "  MALGUARD AI — Container Runtime Initialization          "
echo "  FastAPI + Official ClamAV Engine + Random Forest ML    "
echo "=========================================================="

# Ensure runtime directories exist with correct permissions
mkdir -p /var/run/clamav /var/log/clamav /var/lib/clamav
chown -R clamav:clamav /var/run/clamav /var/log/clamav /var/lib/clamav
chmod 750 /var/run/clamav /var/log/clamav

# Clean any stale status flags from previous container runs
rm -f /var/run/clamav/clamd.* /tmp/clamd.*

# Verify required signature databases exist before starting
if [ ! -f /var/lib/clamav/main.cvd ] && [ ! -f /var/lib/clamav/main.cld ]; then
    echo "FATAL: ClamAV signature database (main.cvd) is missing!" >&2
    touch /var/run/clamav/clamd.failed /tmp/clamd.failed
    exit 1
fi
if [ ! -f /var/lib/clamav/daily.cvd ] && [ ! -f /var/lib/clamav/daily.cld ]; then
    echo "FATAL: ClamAV daily database (daily.cvd) is missing!" >&2
    touch /var/run/clamav/clamd.failed /tmp/clamd.failed
    exit 1
fi

# Mark status as starting immediately
touch /var/run/clamav/clamd.starting /tmp/clamd.starting

# Launch genuine clamd daemon asynchronously in background
echo "[1/2] Launching ClamAV daemon (clamd) asynchronously in background..."
/usr/sbin/clamd --config-file=/etc/clamav/clamd.conf --foreground=false || {
    echo "ERROR: Failed to launch clamd!" >&2
    rm -f /var/run/clamav/clamd.starting /tmp/clamd.starting
    touch /var/run/clamav/clamd.failed /tmp/clamd.failed
}

# Start background monitor to log readiness and detect crashes
(
    echo "[clamd-monitor] Watching clamd daemon startup on 127.0.0.1:3310 in background..."
    READY=0
    for i in $(seq 1 60); do
        if python3 -c "import socket; s = socket.socket(); s.connect(('127.0.0.1', 3310)); s.sendall(b'zPING\x00'); resp = s.recv(1024); s.close(); exit(0 if b'PONG' in resp else 1)" 2>/dev/null; then
            echo "[clamd-monitor] ClamAV daemon is ONLINE and verified on 127.0.0.1:3310 (ready in ${i}s)."
            rm -f /var/run/clamav/clamd.starting /tmp/clamd.starting
            touch /var/run/clamav/clamd.ready /tmp/clamd.ready
            READY=1
            break
        fi
        sleep 1
    done

    if [ "$READY" -ne 1 ]; then
        echo "[clamd-monitor] WARNING: clamd socket did not respond within 60s. Log dump:" >&2
        cat /var/log/clamav/clamav.log 2>/dev/null || true
        rm -f /var/run/clamav/clamd.starting /tmp/clamd.starting
        touch /var/run/clamav/clamd.timeout /tmp/clamd.timeout
    fi
) &

# Determine port from Vercel's PORT environment variable (default: 8000)
LISTEN_PORT="${PORT:-8000}"
echo "=========================================================="
echo "  [2/2] Starting FastAPI immediately on 0.0.0.0:${LISTEN_PORT}"
echo "=========================================================="

# Exec uvicorn immediately as PID 1 so Vercel port probe succeeds at once
exec uvicorn app.main:app --host 0.0.0.0 --port "${LISTEN_PORT}"
