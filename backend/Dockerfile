FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    CLAMAV_HOST=127.0.0.1 \
    CLAMAV_PORT=3310 \
    PORT=8000

# Install official ClamAV engine, daemon, freshclam updater, and system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Run freshclam to download authentic Cisco Talos virus signature databases (~110 MB)
# Strictly verify required database files exist and fail build if missing
RUN freshclam --verbose && \
    (test -s /var/lib/clamav/main.cvd || test -s /var/lib/clamav/main.cld) && \
    (test -s /var/lib/clamav/daily.cvd || test -s /var/lib/clamav/daily.cld) && \
    (test -s /var/lib/clamav/bytecode.cvd || test -s /var/lib/clamav/bytecode.cld) && \
    echo "=== ClamAV official signature databases verified successfully ==="

# Copy optimized clamd configuration (internal loopback 127.0.0.1:3310, memory-tuned)
COPY clamd.conf /etc/clamav/clamd.conf
RUN chmod 644 /etc/clamav/clamd.conf && \
    mkdir -p /var/run/clamav /var/log/clamav /var/lib/clamav && \
    chown -R clamav:clamav /var/run/clamav /var/log/clamav /var/lib/clamav

WORKDIR /app

# Copy requirements and install Python ML & API dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code, models, and entrypoint
COPY . .

# Ensure entrypoint script is executable
RUN chmod +x /app/entrypoint.sh

# Vercel routes traffic to the port designated by $PORT (defaults to 8000/80)
EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
