# 📂 Centaur-Jarvis · Directory Bruteforcer Module

## Overview
Discovers hidden directories and files on web servers by brute-forcing paths
using a wordlist. Integrates with the Centaur-Jarvis orchestrator via Redis queues.

## Architecture
text

                      ┌────────────────────────┐
                      │     Orchestrator / CLI  │
                      └───────────┬────────────┘
                                  │ LPUSH task JSON
                                  ▼
                         ┌─────────────────┐
                         │  queue:dirbust   │  (Redis List)
                         └────────┬────────┘
                                  │ BRPOP
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│ DIRBUST WORKER (worker.py) │
│ │
│ 1. Validate task payload │
│ 2. Set status → PROCESSING │
│ 3. Resolve wordlist (wordlist_manager.py) │
│ ├─ custom path? → use it │
│ ├─ default exists? → use it │
│ ├─ cached? → use it │
│ └─ auto-download → cache & use │
│ 4. Execute scanner │
│ ├─ ffuf available? → ffuf_runner.py │
│ └─ fallback → gobuster_runner.py │
│ 5. Parse findings (URL, status, size, content-type) │
│ 6. Build result with mandatory data field │
│ 7. LPUSH result → results:incoming │
│ 8. Set status → COMPLETED / FAILED │
└──────────────────────────────────────────────────────────────────┘
│ LPUSH result JSON
▼
┌──────────────────────┐
│ results:incoming │ (Redis List)
└──────────────────────┘

text


## Quick Start

### Prerequisites
```bash
# Install ffuf (primary)
go install github.com/ffuf/ffuf/v2@latest

# OR install gobuster (fallback)
go install github.com/OJ/gobuster/v3@latest

# Python deps
pip install redis pyyaml requests
Run the Worker
Bash

cd /path/to/centaur-jarvis
python -m modules.dirbust.worker
Push a Test Task
Bash

redis-cli LPUSH queue:dirbust '{
  "task_id": "dirbust-001",
  "target": "http://localhost:42000",
  "extensions": ["php","asp"],
  "threads": 10,
  "recursive": false
}'
Check Results
Bash

redis-cli LRANGE results:incoming 0 -1
redis-cli HGETALL task:dirbust-001
Task Payload Schema
Field	Type	Required	Default	Description
task_id	string	✅	—	Unique task identifier
target	string	✅	—	Base URL (http/https)
wordlist	string	❌	config default	Custom wordlist path
extensions	list[str]	❌	config defaults	File extensions to try
threads	int	❌	40	Concurrent threads
delay	float	❌	0.1	Delay between requests (seconds)
recursive	bool	❌	false	Enable recursive scanning
depth	int	❌	3	Maximum recursion depth
Result Structure
JSON

{
  "task_id": "dirbust-001",
  "module": "dirbust",
  "status": "COMPLETED",
  "target": "http://localhost:42000",
  "timestamp": "2024-01-15T10:30:00Z",
  "elapsed_seconds": 12.5,
  "tool_used": "ffuf",
  "data": {
    "findings": [
      {
        "url": "http://localhost:42000/admin",
        "status_code": 200,
        "content_length": 1234,
        "content_type": "text/html",
        "redirect_location": "",
        "input_word": "admin",
        "lines": 50,
        "words": 200,
        "duration_ms": 45.2,
        "host": "localhost:42000"
      }
    ],
    "stats": {
      "total_requests": 4614,
      "total_findings": 12,
      "errors": 0,
      "elapsed_seconds": 12.5,
      "tool": "ffuf",
      "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
      "extensions": ["php", "asp"],
      "threads": 10,
      "recursive": false
    }
  }
}
Edge Cases Handled
#	Edge Case	Mitigation
1	Wordlist file not found	Auto-download; fail if download fails
2	ffuf binary missing	Fallback to gobuster; TOOL_MISSING
3	Target unreachable / timeout	TIMEOUT error type in result
4	Rate limit (429)	Configurable delay; per-host rate limit
5	Very large wordlist	Stream processing (ffuf handles it)
6	Duplicate task on resume	Orchestrator deduplication; worker runs
7	Deep recursive scan	Clamped to max_recursion_depth
8	Malformed ffuf JSON	Skip line, log warning, continue
9	Redis connection lost	Buffer up to 100 results in memory
Configuration
See config.yaml for all options. Key settings:

wordlist.auto_download: Auto-download SecLists wordlist if not found
execution.default_threads: Default concurrency
execution.timeout: Per-task timeout
rate_limit.per_host_rate: Advisory rate limit
