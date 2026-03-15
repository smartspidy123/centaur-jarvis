# 🕵️ Centaur-Jarvis — Recon Workers Module

## Overview
The Recon Workers module executes deterministic reconnaissance tasks on
cloud/VPS workers (or local Kali). It consumes tasks from Redis, runs
security tools via subprocess, parses their output, and pushes structured
results back to the orchestrator.

## Quick Start

### Prerequisites
```bash
# Python deps
pip install redis pyyaml psutil

# Security tools (ProjectDiscovery suite)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Start Redis
redis-server
Run the Worker
Bash

python modules/recon/worker.py
# or with custom config:
python modules/recon/worker.py -c /path/to/config.yaml
Submit a Test Task
Bash

redis-cli LPUSH queue:recon '{
  "task_id": "test-001",
  "type": "RECON_SUBDOMAIN",
  "target": "example.com",
  "params": {"recursive": true, "threads": 20}
}'
Check Results
Bash

redis-cli LRANGE results:incoming 0 -1
Docker
Bash

docker build -t jarvis-recon-worker -f modules/recon/Dockerfile .
docker run -e REDIS_HOST=host.docker.internal jarvis-recon-worker
Supported Task Types
Task Type	Tool	Description
RECON_SUBDOMAIN	subfinder	Subdomain enumeration
RECON_HTTPX	httpx	HTTP probing & tech detection
RECON_NUCLEI	nuclei	Vulnerability scanning
RECON_PORTSCAN	naabu	Port scanning
Architecture
See the Deep-Dive DNA section below for lifecycle diagrams and edge-case tables.

text


---

## 11. `requirements.txt`
redis>=5.0.0
pyyaml>=6.0
psutil>=5.9.0
