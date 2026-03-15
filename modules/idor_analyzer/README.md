# IDOR Analyzer Module — Centaur‑Jarvis

## Overview

The **IDOR Analyzer** detects **Insecure Direct Object Reference (IDOR)**
and **Broken Object Level Authorization (BOLA)** vulnerabilities. It
compares HTTP responses from two authenticated user sessions against
the same API endpoints to determine whether one user can access
another user's resources without proper authorization.

## Architecture

Redis queue:idor ──▶ analyzer.py (worker)
│
├──▶ session_manager.py (auth tokens)
├──▶ HTTP requests as User A & User B
└──▶ comparators.py (response diff)
│
▼
Redis results:incoming

text


## Quick Start

### 1. Install dependencies

```bash
pip install redis pyyaml requests

2. Start the worker

Bash

python -m modules.idor_analyzer.analyzer
# or
python modules/idor_analyzer/analyzer.py

3. Push a test task

Bash

redis-cli LPUSH queue:idor '{
  "task_id": "idor-001",
  "target": "http://localhost:42000/api",
  "endpoints": ["/user/1", "/user/2"],
  "method": "GET",
  "auth_tokens": {
    "userA": "token_a",
    "userB": "token_b"
  }
}'

4. Check results

Bash

redis-cli LRANGE results:incoming 0 -1

Task Payload Schema
Field	Type	Required	Default	Description
task_id	string	Yes	—	Unique identifier
target	string	Yes	—	Base URL (e.g., http://api.local)
endpoints	list of strings	Yes	—	Paths to test (e.g., ["/user/1"])
method	string	No	GET	HTTP method
params	dict	No	null	Query parameters
body	any	No	null	Request body (POST/PUT/PATCH)
headers	dict	No	{}	Additional HTTP headers
auth_tokens	dict	No*	null	Tokens for userA & userB

*If auth_tokens is not provided, tokens are fetched from Redis keys
auth:token:userA and auth:token:userB.
Result Structure

JSON

{
  "task_id": "idor-001",
  "module": "idor_analyzer",
  "status": "COMPLETED",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "findings": [
      {
        "type": "IDOR",
        "severity": "HIGH",
        "confidence": 0.95,
        "endpoint": "/user/1",
        "url": "http://api.local/user/1",
        "method": "GET",
        "details": { "..." },
        "recommendation": "Implement object-level authorization…",
        "owasp": "API1:2023 Broken Object Level Authorization",
        "cwe": "CWE-639"
      }
    ],
    "stats": {
      "total_endpoints": 2,
      "tested": 2,
      "suspicious": 1,
      "errors": 0
    }
  }
}

Configuration

See config.yaml for all options. Key environment variable overrides:

    REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD

Edge Cases
#	Edge Case	Handling
1	Auth tokens missing	FAILED with error_type=AUTH_MISSING
2	Target unreachable	Retry with backoff; then report error per endpoint
3	False positive diffs	Configurable ignore lists + similarity threshold
4	Dynamic fields	Regex-based field stripping before comparison
5	Large response bodies	Truncation at configurable max_response_bytes
6	Redis connection lost	In-memory buffer (max 100 results) + retry
7	Invalid task JSON	Logged and skipped
8	SIGTERM during processing	Finish current endpoint, drain buffer, exit

┌─────────────────────────────────────────────────────────────────────────────────┐
│                         IDOR ANALYZER MODULE WORKFLOW                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Redis queue:idor                                                               │
│       │                                                                         │
│       ▼                                                                         │
│  ┌──────────────┐    ┌───────────────────┐    ┌─────────────────────┐           │
│  │  analyzer.py  │───▶│ session_manager.py │───▶│  Fetch/Validate     │           │
│  │  (Worker)     │    │  get_session_auth  │    │  Auth Tokens        │           │
│  └──────┬───────┘    └───────────────────┘    └─────────────────────┘           │
│         │                                                                       │
│         ▼                                                                       │
│  ┌──────────────────────────────────────────────┐                               │
│  │  For each endpoint in task.endpoints:         │                               │
│  │                                               │                               │
│  │  ┌─────────────┐       ┌─────────────┐       │                               │
│  │  │ HTTP Request │       │ HTTP Request │       │                               │
│  │  │  as User A   │       │  as User B   │       │                               │
│  │  └──────┬──────┘       └──────┬──────┘       │                               │
│  │         │                      │              │                               │
│  │         ▼                      ▼              │                               │
│  │  ┌──────────────────────────────────┐        │                               │
│  │  │     comparators.py               │        │                               │
│  │  │  compare_responses(resp_a,resp_b)│        │                               │
│  │  │                                  │        │                               │
│  │  │  1. Normalize (strip dynamic)    │        │                               │
│  │  │  2. Compare status codes         │        │                               │
│  │  │  3. Compare headers              │        │                               │
│  │  │  4. Compare body (JSON deep diff)│        │                               │
│  │  │  5. Similarity ratio check       │        │                               │
│  │  │  6. IDOR suspicion heuristics    │        │                               │
│  │  └──────────┬───────────────────────┘        │                               │
│  │             │                                 │                               │
│  │             ▼                                 │                               │
│  │  ┌─────────────────────┐                     │                               │
│  │  │ Finding generated?  │──Yes──▶ Append      │                               │
│  │  │ (suspicious=True)   │        to findings  │                               │
│  │  └─────────────────────┘                     │                               │
│  └──────────────────────────────────────────────┘                               │
│         │                                                                       │
│         ▼                                                                       │
│  ┌────────────────────────────────────┐                                         │
│  │  Build TaskResult                  │                                         │
│  │  {                                 │                                         │
│  │    "task_id": "...",               │                                         │
│  │    "status": "COMPLETED"/"FAILED", │                                         │
│  │    "data": {                       │                                         │
│  │      "findings": [...],            │                                         │
│  │      "stats": {...}                │                                         │
│  │    }                               │                                         │
│  │  }                                 │                                         │
│  └────────────┬───────────────────────┘                                         │
│               │                                                                 │
│               ▼                                                                 │
│      Redis results:incoming                                                     │
│                                                                                 │
│  Telemetry: JSON logs at every stage                                            │
│  Shutdown: SIGTERM → finish current endpoint → drain buffer → exit              │
│  Fallback: memory buffer (max 100) if Redis write fails                         │
└─────────────────────────────────────────────────────────────────────────────────┘
