#!/bin/bash
set -e

echo "=========================================================="
echo "  MALGUARD AI — Container Runtime Initialization          "
echo "  FastAPI + Official ClamAV Engine + Random Forest ML    "
echo "=========================================================="

# Ensure proper permissions on clamd runtime directories
mkdir -p /var/run/clamav /var/log/clamav /var/lib/clamav
chown -R clamav:clamav /var/run/clamav /var/log/clamav /var/lib/clamav
chmod 750 /var/run/clamav /var/log/clamav

# Verify required signature databases exist before starting
if [ ! -f /var/lib/clamav/main.cvd ] && [ ! -f /var/lib/clamav/main.cld ]; then
    echo "FATAL: ClamAV signature database (main.cvd) is missing!" >&2
    exit 1
fi
if [ ! -f /var/lib/clamav/daily.cvd ] && [ ! -f /var/lib/clamav/daily.cld ]; then
    echo "FATAL: ClamAV daily database (daily.cvd) is missing!" >&2
    exit 1
fi

echo "[1/2] Starting genuine ClamAV daemon (clamd) internally on 127.0.0.1:3310..."
/usr/sbin/clamd --config-file=/etc/clamav/clamd.conf --foreground=false

# Wait up to 30 seconds for clamd socket to bind and respond to PING
echo "Waiting for clamd socket on 127.0.0.1:3310..."
READY=0
for i in $(seq 1 30); do
    if python3 -c "import socket; s = socket.socket(); s.connect(('127.0.0.1', 3310)); s.sendall(b'zPING\x00'); resp = s.recv(1024); s.close(); exit(0 if b'PONG' in resp else 1)" 2>/dev/null; then
        echo "ClamAV daemon ready and verified on 127.0.0.1:3310 (attempt $i)."
        READY=1
        break
    fi
    sleep 1
done

if [ "$READY" -ne 1 ]; then
    echo "WARNING: ClamAV daemon did not respond to PING within 30s. Inspecting clamd log:" >&2
    cat /var/log/clamav/clamav.log 2>/dev/null || true
fi

# Determine port from Vercel's PORT environment variable (default: 8000)
LISTEN_PORT="${PORT:-8000}"
echo "[2/2] Launching FastAPI on 0.0.0.0:${LISTEN_PORT}..."

# Exec uvicorn as PID 1 to handle process signals cleanly
exec uvicorn app.main:app --host 0.0.0.0 --port "${LISTEN_PORT}"
