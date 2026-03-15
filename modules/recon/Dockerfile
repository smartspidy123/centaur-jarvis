# ===========================================================================
# Centaur-Jarvis Recon Worker — Container Image
# ===========================================================================
# Multi-stage build:
#   Stage 1: Install Go-based security tools
#   Stage 2: Slim Python runtime with tools copied in
# ===========================================================================

# ── Stage 1: Tool Builder ──────────────────────────────────────────────────
FROM golang:1.22-alpine AS tool-builder

RUN apk add --no-cache git build-base

# Install ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# ── Stage 2: Runtime ──────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="Centaur-Jarvis Security Architecture Team"
LABEL description="Recon Worker — deterministic reconnaissance task executor"

# System deps for naabu (libpcap)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap-dev \
        ca-certificates \
        && \
    rm -rf /var/lib/apt/lists/*

# Copy tools from builder
COPY --from=tool-builder /root/go/bin/subfinder /usr/local/bin/subfinder
COPY --from=tool-builder /root/go/bin/httpx     /usr/local/bin/httpx
COPY --from=tool-builder /root/go/bin/nuclei    /usr/local/bin/nuclei
COPY --from=tool-builder /root/go/bin/naabu     /usr/local/bin/naabu

# Verify tools
RUN subfinder -version && \
    httpx -version && \
    nuclei -version && \
    naabu -version

# Update nuclei templates
RUN nuclei -update-templates || true

# Python deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY . .

# Logs directory
RUN mkdir -p /app/logs

# Non-root user for security
RUN useradd -r -s /bin/false reconworker && \
    chown -R reconworker:reconworker /app
# Note: naabu needs NET_RAW capability; run container with --cap-add=NET_RAW
# or run as root if necessary for raw sockets

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import redis; r=redis.Redis(host='${REDIS_HOST:-127.0.0.1}'); r.ping()" || exit 1

ENTRYPOINT ["python", "modules/recon/worker.py"]
CMD ["-c", "modules/recon/config.yaml"]
