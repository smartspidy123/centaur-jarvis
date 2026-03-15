# Playwright Renderer Module (`playwright_rend`)

## Overview

The **Playwright Renderer** module is a component of the Centaur‑Jarvis VAPT
agent.  It uses a headless Chromium browser (via
[Playwright](https://playwright.dev/python/)) to render Single Page
Applications (SPAs) and intercept XHR / Fetch API calls to discover:

- **Endpoints** (URLs, methods, parameters, request/response bodies)
- **Authentication tokens** (JWT, Bearer, cookies, custom headers)
- **HTML form structures** (action, method, input fields)

## Architecture

Redis queue:playwright ──▶ renderer.py (worker)
│
├──▶ intercept.py (subprocess, headless browser)
│ ├── Navigates to target URL
│ ├── Intercepts XHR/Fetch requests
│ ├── Extracts forms from DOM
│ └── Outputs JSON lines to stdout
│
└──▶ Redis results:incoming (structured result)

text


## Installation

```bash
pip install playwright redis pyyaml
playwright install chromium

Usage
Start the worker

Bash

# Using default config
python -m modules.playwright_rend.renderer

# With custom config
python -m modules.playwright_rend.renderer --config /path/to/config.yaml

Submit a task (example)

Python

import json, redis
r = redis.Redis()
task = {
    "task_id": "pw-001",
    "target": "https://example.com",
    "timeout": 30,
    "extract_forms": True,
    "click_elements": ["button.load-more"],
    "max_depth": 2,
}
r.lpush("queue:playwright", json.dumps(task))

Task fields
Field	Type	Required	Default	Description
task_id	string	No	UUID	Unique task identifier
target	string	Yes	—	URL to render
timeout	int	No	30	Navigation timeout in seconds
wait_for_selector	string	No	null	CSS selector to wait for after load
click_elements	list[str]	No	null	CSS selectors to click for discovery
extract_forms	bool	No	true	Extract HTML forms from DOM
max_depth	int	No	1	Recursion depth for clicking
cookies	list[dict]	No	null	Browser cookies for authenticated scan
extra_headers	dict	No	null	Extra HTTP headers to inject
Result structure

JSON

{
  "task_id": "pw-001",
  "module": "playwright_rend",
  "status": "COMPLETED",
  "data": {
    "endpoints": [...],
    "forms": [...],
    "tokens": [...],
    "stats": {
      "total_endpoints": 42,
      "total_forms": 2,
      "total_tokens": 1,
      "requests_captured": 42,
      "elapsed_seconds": 12.3,
      "exit_code": 0
    }
  }
}

Configuration

See config.yaml for all options. Key settings:

    browser.headless: Run browser without GUI (default: true)
    browser.timeout: Navigation timeout in ms (default: 30000)
    extraction.max_requests: Cap on intercepted requests (default: 500)
    extraction.max_response_body: Truncate response bodies (default: 10240 bytes)

Edge Cases Handled

    Target unreachable → TIMEOUT / FAILED
    Browser crash → BROWSER_ERROR
    Infinite redirects → capped at 10
    Redis unavailable → results buffered in memory (max 100)
    SIGTERM → graceful shutdown after current task
    Large response bodies → truncated
    Non-text responses → skipped

Running intercept.py standalone (debug)

Bash

python modules/playwright_rend/intercept.py \
    --target "https://example.com" \
    --timeout 30000 \
    --extract-forms true

text


---

## Integration Notes

1. **Orchestrator Integration**: The orchestrator pushes tasks to `queue:playwright` after initial recon (e.g., from `httpx` module discovering SPA indicators like `<script>` tags with framework bundles). The task payload flows directly from the orchestrator's decision engine.

2. **Token Harvester Feed-Forward**: Tokens discovered by this module (in `data.tokens`) can be extracted by a downstream **Token Harvester** module. The orchestrator reads from `results:incoming`, identifies `playwright_rend` results containing tokens, and forwards them to `queue:token_harvester`.

3. **CLI Process Management**: The CLI starts this worker via:
   ```bash
   python -m modules.playwright_rend.renderer --config config.yaml &

The SIGTERM handler ensures clean shutdown when the process manager stops the worker.

    Horizontal Scaling: Multiple worker instances can consume from the same queue:playwright queue — Redis BRPOP provides atomic dequeue, preventing duplicate processing.

    Result Schema Compliance: The result always contains the mandatory data field with endpoints, forms, tokens, and stats. The status field is always uppercase (COMPLETED, FAILED, PROCESSING, TIMEOUT).

    Dependency on shared Package: The module gracefully degrades when shared.logger or shared.schemas are unavailable, providing built-in fallbacks. This allows independent development and testing.

    Subprocess Isolation: intercept.py runs as a separate process. If the browser crashes, OOMs, or segfaults, the worker process survives and marks the task as FAILED. The subprocess timeout is set to task.timeout + subprocess_extra_timeout (default 15s buffer).

┌─────────────────────────────────────────────────────────────────────────────┐
│                        PLAYWRIGHT RENDERER MODULE                          │
│                                                                            │
│  ┌──────────┐    ┌─────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Redis    │    │  renderer.py│    │ intercept.py │    │   Redis      │  │
│  │  Queue    │───▶│  (Worker)   │───▶│ (Browser     │───▶│  Results     │  │
│  │queue:     │    │             │    │  Automation)  │    │results:      │  │
│  │playwright │    │ • Validate  │    │              │    │incoming      │  │
│  └──────────┘    │ • Launch    │    │ • Navigate   │    └──────────────┘  │
│                  │ • Parse     │    │ • Intercept  │                      │
│                  │ • Report    │    │ • Extract    │    ┌──────────────┐  │
│                  └─────────────┘    │ • Output     │    │ Redis Hash   │  │
│                        │           │   JSON lines │    │ task:{id}    │  │
│                        │           └──────────────┘    │ status field │  │
│                        │                  │            └──────────────┘  │
│                        │                  │                   ▲          │
│                        │                  ▼                   │          │
│                        │           ┌──────────────┐          │          │
│                        │           │  stdout pipe │          │          │
│                        │           │  (JSON lines)│          │          │
│                        │           └──────────────┘          │          │
│                        └─────────────────────────────────────┘          │
│                                                                          │
│  SIGNAL HANDLING:                                                        │
│  ┌──────────┐                                                            │
│  │ SIGTERM   │──▶ Set shutdown_event ──▶ Finish current task ──▶ Exit   │
│  └──────────┘                                                            │
│                                                                          │
│  REDIS FALLBACK:                                                         │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │ Push to   │──▶│ ConnectionErr│──▶│ Buffer in    │──▶ Retry on next  │
│  │ Redis     │   │              │   │ memory (≤100)│    cycle           │
│  └──────────┘    └──────────────┘    └──────────────┘                   │
│                                                                          │
│  INTERCEPTION FLOW (inside intercept.py):                                │
│                                                                          │
│  Browser Launch ──▶ Set request/response handlers ──▶ Navigate          │
│       │                                                                  │
│       ▼                                                                  │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │  For each network request:                              │            │
│  │  1. Check if XHR or Fetch (resource_type)               │            │
│  │  2. Extract URL, method, headers, body                  │            │
│  │  3. Match response to request                           │            │
│  │  4. Detect auth tokens (JWT, Bearer, cookies)           │            │
│  │  5. Emit JSON line to stdout                            │            │
│  │  6. Increment counter, stop if >= max_requests          │            │
│  └─────────────────────────────────────────────────────────┘            │
│       │                                                                  │
│       ▼                                                                  │
│  ┌─────────────────────────────────────────────────────────┐            │
│  │  After page load:                                       │            │
│  │  1. Wait for selector (if provided)                     │            │
│  │  2. Click elements (if provided, up to max_depth)       │            │
│  │  3. Extract forms from DOM                              │            │
│  │  4. Emit form findings as JSON lines                    │            │
│  └─────────────────────────────────────────────────────────┘            │
│       │                                                                  │
│       ▼                                                                  │
│  Exit with code 0 (success) or non-zero (error)                        │
└─────────────────────────────────────────────────────────────────────────────┘
