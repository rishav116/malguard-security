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

# Configure clamd for internal-only loopback communication (127.0.0.1:3310)
# Port 3310 is strictly bound to 127.0.0.1 and NEVER exposed outside the container
RUN sed -i 's/^#*TCPSocket .*/TCPSocket 3310/' /etc/clamav/clamd.conf && \
    grep -q "^TCPSocket " /etc/clamav/clamd.conf || echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    sed -i 's/^#*TCPAddr .*/TCPAddr 127.0.0.1/' /etc/clamav/clamd.conf && \
    grep -q "^TCPAddr " /etc/clamav/clamd.conf || echo "TCPAddr 127.0.0.1" >> /etc/clamav/clamd.conf && \
    sed -i 's/^#*StreamMaxLength .*/StreamMaxLength 25M/' /etc/clamav/clamd.conf && \
    sed -i 's/^#*MaxScanSize .*/MaxScanSize 100M/' /etc/clamav/clamd.conf && \
    sed -i 's/^#*MaxFileSize .*/MaxFileSize 25M/' /etc/clamav/clamd.conf && \
    sed -i 's/^#*MaxThreads .*/MaxThreads 2/' /etc/clamav/clamd.conf && \
    grep -q "^MaxThreads " /etc/clamav/clamd.conf || echo "MaxThreads 2" >> /etc/clamav/clamd.conf && \
    sed -i 's/^#*ConcurrentDatabaseReload .*/ConcurrentDatabaseReload no/' /etc/clamav/clamd.conf && \
    grep -q "^ConcurrentDatabaseReload " /etc/clamav/clamd.conf || echo "ConcurrentDatabaseReload no" >> /etc/clamav/clamd.conf && \
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
