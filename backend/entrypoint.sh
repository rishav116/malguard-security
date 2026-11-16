#!/bin/bash
set -e

echo "=========================================================="
echo "  MALGUARD AI — Container Runtime Initialization          "
echo "  FastAPI + Official ClamAV Engine + Random Forest ML    "
echo "=========================================================="

# Ensure runtime directories exist with correct permissions
mkdir -p /var/run/clamav /var/log/clamav /var/lib/clamav /tmp
chown -R clamav:clamav /var/run/clamav /var/log/clamav /var/lib/clamav
chmod 750 /var/run/clamav /var/log/clamav

# Clean any stale status flags from previous container runs
rm -f /var/run/clamav/clamd.* /tmp/clamd.*

# Verify required signature databases exist before starting
if [ ! -f /var/lib/clamav/main.cvd ] && [ ! -f /var/lib/clamav/main.cld ]; then
    echo "FATAL: ClamAV signature database (main.cvd) is missing!" >&2
    touch /tmp/clamd.failed
    exit 1
fi
if [ ! -f /var/lib/clamav/daily.cvd ] && [ ! -f /var/lib/clamav/daily.cld ]; then
    echo "FATAL: ClamAV daily database (daily.cvd) is missing!" >&2
    touch /tmp/clamd.failed
    exit 1
fi

# Launch ClamAV Lifecycle Supervisor asynchronously in background
echo "[1/2] Launching ClamAV Lifecycle Supervisor asynchronously in background..."
python3 -u /app/app/services/clamd_supervisor.py &

# Determine port from Vercel's PORT environment variable (default: 8000)
LISTEN_PORT="${PORT:-8000}"
echo "=========================================================="
echo "  [2/2] Starting FastAPI immediately on 0.0.0.0:${LISTEN_PORT}"
echo "=========================================================="

# Exec uvicorn immediately as PID 1 so Vercel port probe succeeds at once
exec uvicorn app.main:app --host 0.0.0.0 --port "${LISTEN_PORT}"
