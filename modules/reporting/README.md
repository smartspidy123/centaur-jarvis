┌─────────────────────────────────────────────────────────────────────────────┐
│                         REPORTING MODULE DATA FLOW                          │
│                                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Redis    │    │   Data       │    │  Aggregation │    │  Formatters  │  │
│  │  Store    │───▶│  Collector   │───▶│  Engine      │───▶│  Pipeline    │  │
│  │          │    │              │    │              │    │              │  │
│  │task:*    │    │- fetch results│    │- group by    │    │┌────────────┐│  │
│  │task:*:   │    │- fetch meta  │    │  severity    │    ││  HTML/Jinja ││  │
│  │ result   │    │- validate    │    │- count stats │    │├────────────┤│  │
│  │scan_index│    │- filter      │    │- sort        │    ││  JSON      ││  │
│  │          │    │- fallback    │    │- deduplicate │    │├────────────┤│  │
│  └──────────┘    └──────────────┘    │- enrich      │    ││  Text/CLI  ││  │
│       │                │              └──────────────┘    │└────────────┘│  │
│       │                │                     │            └──────────────┘  │
│       │          ┌─────▼─────┐               │                   │         │
│       │          │  Edge Case │               │                   │         │
│       │          │  Handler   │               │            ┌──────▼──────┐  │
│       │          │            │               │            │  File Writer │  │
│       │          │- no results│               │            │             │  │
│       │          │- malformed │               │            │- timestamp  │  │
│       │          │- missing   │               │            │- fallback   │  │
│       │          │  metadata  │               │            │  directory  │  │
│       │          │- redis fail│               │            │- permissions│  │
│       │          └────────────┘               │            └──────┬──────┘  │
│       │                                      │                   │         │
│       │         ┌────────────────────────────┐│            ┌──────▼──────┐  │
│       └────────▶│   Telemetry / Logger       │◀────────────│  Reports    │  │
│                 │                            │             │  on Disk    │  │
│                 │- timing metrics            │             │             │  │
│                 │- error counts              │             │- report_    │  │
│                 │- findings stats            │             │  SCAN_TS.   │  │
│                 │- skipped tasks             │             │  {html,json │  │
│                 └────────────────────────────┘             │   ,txt}     │  │
│                                                            └─────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘

ORCHESTRATOR INTEGRATION:
┌──────────────┐     ┌───────────────┐     ┌──────────────────┐
│ Orchestrator │────▶│ ReportEngine  │────▶│ Generated Reports│
│ (post-scan)  │     │ .generate()   │     │ (all formats)    │
└──────────────┘     └───────────────┘     └──────────────────┘


modules/reporting/
├── __init__.py
├── __main__.py
├── generator.py
├── formatters.py
├── config.yaml
├── templates/
│   └── report.html.j2
└── README.md


# 📝 Centaur-Jarvis Reporting Module

> Generates comprehensive VAPT reports from completed scan results stored in Redis.

## Architecture

```text
Redis (task:*:result) → DataCollector → Aggregator → Formatters → Files on Disk
Quick Start
Standalone CLI
Bash

# All scans, all formats
python -m modules.reporting.generator

# Specific scan
python -m modules.reporting.generator --scan-id SCAN-001

# Custom output
python -m modules.reporting.generator --scan-id SCAN-001 --output-dir ./my-reports --formats html json

# Include raw output
python -m modules.reporting.generator --scan-id SCAN-001 --include-raw
Programmatic (from Orchestrator)
Python

from modules.reporting import ReportEngine, generate_report

# Quick one-liner
paths = generate_report(scan_id="scan-001")

# Full control
engine = ReportEngine()
paths = engine.generate(
    scan_id="scan-001",
    output_dir="./reports",
    formats=["html", "json"]
)

# With pre-collected data (no Redis needed)
paths = engine.generate_from_data(
    tasks=my_tasks_list,
    findings=my_findings_list,
    scan_id="scan-001"
)
Redis Data Contract
Expected Keys
Key Pattern	Type	Description
task:*:result	String (JSON)	Task result payload
task:{id}	Hash	Task metadata (target, type, state, scan_id)
Expected Result JSON Structure
JSON

{
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "data": {
    "findings": [
      {
        "template": "cve-2021-xxxxx",
        "severity": "high",
        "matched-at": "http://target:3000/api",
        "description": "...",
        "remediation": "...",
        "curl-command": "curl ..."
      }
    ]
  }
}
Output Formats
Format	Extension	Use Case
HTML	.html	Executive/browser-readable report
JSON	.json	Machine parsing, CI/CD integration
Text	.txt	Terminal/CLI quick view
Edge Cases Mitigated
#	Edge Case	Mitigation
1	No results in Redis	Empty report generated with "no findings" message
2	Malformed result JSON	Logged with context, skipped, error counter incremented
3	Missing task metadata hash	Defaults applied (type=unknown, target=N/A)
4	Large findings set	HTML paginated at 500 (configurable), JSON always complete
5	Output directory not writable	Fallback to CWD + warning logged
6	Jinja2 template missing	Hardcoded fallback HTML used automatically
7	Redis connection failure	Logged, empty report generated gracefully
8	Jinja2 not installed	Fallback HTML renderer (no dependency)
9	yaml not installed	Hardcoded default config used
10	redis package not installed	Clear error message, empty data
11	shared.logger not available	stdlib logging fallback
12	shared.schemas not available	Operates without schema validation
13	Duplicate findings	Deduplication by (template, endpoint, severity)
14	Unknown severity values	Mapped to "unknown" category
15	Nuclei JSONL stdout parsing	Auto-detected and parsed if no explicit findings
16	Non-dict finding objects	Skipped with debug log
17	File write permission error	Fallback path attempted
18	Task ID with colons	Properly extracted from key pattern
19	Empty stdout for nuclei	Returns empty findings list
20	KeyboardInterrupt during CLI	Graceful exit with message
Remaining Loopholes & Future Improvements
PDF Export: Add wkhtmltopdf or weasyprint for PDF generation
Email Integration: Auto-send reports via SMTP after generation
Diff Reports: Compare findings between scans (regression tracking)
SARIF Output: For GitHub/GitLab security tab integration
Real-time Streaming: WebSocket-based live report updates during scan
Finding Correlation: Cross-reference findings across task types (e.g., nmap port → nuclei vuln)
CVSS Score Lookup: Enrich findings with CVSS scores from NVD API
Internationalization: Multi-language report templates
Compressed Output: Gzip large JSON/HTML reports
Cloud Storage: Upload to S3/GCS after generation
Performance Considerations
Redis SCAN vs KEYS: Uses scan_iter() with cursor-based iteration (memory-safe for large datasets)
Streaming Processing: Findings processed one-at-a-time, not loaded all into memory first
Deduplication: O(n) set-based dedup, not O(n²) comparison
HTML Pagination: Prevents browser crashes on 10K+ findings
Lazy Template Loading: Jinja2 template compiled once per engine instance
String Concatenation: Uses list join pattern, not repeated string concat
Integration Notes
Orchestrator Post-Scan Hook
Python

# In orchestrator.py, after all tasks complete:
from modules.reporting import generate_report

def on_scan_complete(scan_id: str):
    try:
        paths = generate_report(scan_id=scan_id)
        logger.info(f"Reports generated: {paths}")
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
CI/CD Pipeline
YAML

# In GitHub Actions or similar
- name: Generate VAPT Report
  run: |
    python -m modules.reporting.generator \
      --scan-id ${{ env.SCAN_ID }} \
      --formats json \
      --output-dir ./artifacts/reports

- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: vapt-report
    path: ./artifacts/reports/
Testing
Manual Test with Redis
Bash

# 1. Push a test result to Redis
redis-cli SET "task:juice-007:result" '{"exit_code":0,"stdout":"","data":{"findings":[{"template":"cve-2021-3449","severity":"high","matched-at":"http://juice-shop:3000/api","description":"OpenSSL NULL pointer dereference","remediation":"Upgrade OpenSSL to 1.1.1k+","curl-command":"curl -k https://juice-shop:3000/api"}]}}'

# 2. Set task metadata
redis-cli HSET "task:juice-007" type nuclei target juice-shop:3000 state completed scan_id SCAN-TEST-001

# 3. Run report generation
python -m modules.reporting.generator --scan-id SCAN-TEST-001

# 4. Check output
ls -la reports/
# Open HTML in browser, inspect JSON, read text output
Automated Test Script
Python

import redis
import json
import subprocess

# Setup
r = redis.Redis(decode_responses=True)

# Push test data
r.set("task:test-001:result", json.dumps({
    "exit_code": 0,
    "data": {
        "findings": [
            {
                "template": "cve-2021-44228",
                "severity": "critical",
                "matched-at": "http://target:8080/api",
                "description": "Log4Shell RCE",
                "remediation": "Upgrade log4j to 2.17.0+",
                "curl-command": "curl http://target:8080/api"
            },
            {
                "template": "misconfig-cors",
                "severity": "medium",
                "matched-at": "http://target:8080",
                "description": "CORS misconfiguration",
                "curl-command": "curl -H 'Origin: evil.com' http://target:8080"
            }
        ]
    }
}))
r.hset("task:test-001", mapping={
    "type": "nuclei",
    "target": "target:8080",
    "state": "completed",
    "scan_id": "TEST-SCAN"
})

# Run
result = subprocess.run(
    ["python", "-m", "modules.reporting.generator", "--scan-id", "TEST-SCAN"],
    capture_output=True, text=True
)
print(result.stdout)
assert result.returncode == 0

# Cleanup
r.delete("task:test-001:result", "task:test-001")
text


---

## 🧪 Testing Instructions (Step-by-Step)

```bash
# =========================================================================
# STEP 1: Ensure Redis is running
# =========================================================================
redis-cli ping   # Should return PONG

# =========================================================================
# STEP 2: Push a test task (simulating what the orchestrator does)
# =========================================================================
redis-cli SET "task:juice-007:result" '{
  "exit_code": 0,
  "stdout": "[CVE-2021-3449] [high] http://juice-shop:3000/api/products",
  "stderr": "",
  "data": {
    "findings": [
      {
        "template": "CVE-2021-3449",
        "severity": "high",
        "matched-at": "http://juice-shop:3000/api/products",
        "description": "OpenSSL NULL pointer dereference in signature algorithms processing",
        "remediation": "Upgrade OpenSSL to version 1.1.1k or later",
        "curl-command": "curl -k https://juice-shop:3000/api/products"
      },
      {
        "template": "misconfig-x-frame-options",
        "severity": "medium",
        "matched-at": "http://juice-shop:3000/",
        "description": "Missing X-Frame-Options header allows clickjacking",
        "remediation": "Add X-Frame-Options: DENY header",
        "curl-command": "curl -I http://juice-shop:3000/"
      },
      {
        "template": "tech-detect-express",
        "severity": "info",
        "matched-at": "http://juice-shop:3000/",
        "description": "Express.js framework detected",
        "curl-command": "curl -I http://juice-shop:3000/"
      }
    ]
  }
}'

redis-cli HSET "task:juice-007" \
  type nuclei \
  target "juice-shop:3000" \
  state completed \
  scan_id "JUICE-SCAN-001" \
  started_at "2025-01-15T10:00:00Z" \
  completed_at "2025-01-15T10:05:32Z"

# =========================================================================
# STEP 3: Run the reporting module
# =========================================================================
python -m modules.reporting.generator --scan-id JUICE-SCAN-001

# =========================================================================
# STEP 4: Verify output
# =========================================================================
ls -la reports/
# Should show:
#   report_JUICE-SCAN-001_YYYYMMDD_HHMMSS.html
#   report_JUICE-SCAN-001_YYYYMMDD_HHMMSS.json
#   report_JUICE-SCAN-001_YYYYMMDD_HHMMSS.txt

# Open HTML in browser
# Validate JSON:
python -m json.tool reports/report_JUICE-SCAN-001_*.json | head -50

# =========================================================================
# STEP 5: Cleanup
# =========================================================================
redis-cli DEL "task:juice-007:result" "task:juice-007"
📊 Edge Cases Mitigated (Summary Table)
#	Edge Case	Detection Method	Mitigation	Log Level
1	No results in Redis	len(result_keys) == 0	Generate empty report with message	INFO
2	Malformed result JSON	json.JSONDecodeError	Skip entry, increment error counter	ERROR
3	Missing task metadata hash	hgetall returns empty	Apply defaults dict	DEBUG
4	500+ findings in HTML	len > max_findings_per_page	Truncate + warning banner	INFO
5	Output dir not writable	PermissionError on mkdir/write	Fallback to CWD	WARNING
6	Jinja2 template file missing	Path.is_file() check	Hardcoded fallback HTML	WARNING
7	Redis connection refused	redis.ConnectionError	Log + generate empty report	ERROR
8	jinja2 not installed	ImportError guard	Fallback renderer	WARNING
9	pyyaml not installed	ImportError guard	Hardcoded defaults	INFO
10	redis not installed	ImportError guard	Clear error + empty data	ERROR
11	shared.logger missing	ImportError guard	stdlib logging	—
12	Duplicate findings	Set-based dedup on 3-tuple	Remove duplicates, log count	INFO
13	Unknown severity string	Not in severity_order	Map to "unknown"	DEBUG
14	Nuclei JSONL in stdout	Detect task_type == nuclei	Parse line-by-line	DEBUG
15	Non-dict in findings list	isinstance check	Skip with debug log	DEBUG
16	Task ID containing colons	Split/rejoin logic	Handles task:a:b:c:result	—
17	KeyboardInterrupt	except KeyboardInterrupt	Graceful exit code 130	—
18	JSON serialization error	TypeError/ValueError	default=str fallback	ERROR
19	Extremely large raw output	HTML max-height: 200px	CSS overflow + truncation	—
20	Result value is list not dict	isinstance check	Wrap in {"data": value}	WARNING
