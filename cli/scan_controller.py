"""
Scan Controller – Orchestrates phased scanning, task pushing, and activity tracking.

Responsibilities:
- Parse target(s) from CLI input (single URL, file, multiple)
- Execute scan phases in order: recon → fuzzing → sniper → reporting
- Push tasks to Redis queues for workers to consume
- Track current activities, events, errors in thread-safe collections
- Listen for results from Redis and update state accordingly
- Interface between CLI/display and backend workers
- Handle AI router calls with proper fallback

Edge Cases Handled:
- Target file not found → error and exit
- Target unreachable → log error, continue with others
- Redis unavailable → retry with backoff, show error
- AI/RAG unavailable → fallback to deterministic scans
- Empty results from workers → warning event
- Phase timeout → move to next phase with partial results
"""

import json
import time
import uuid
import threading
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timezone
from collections import deque
from urllib.parse import urlparse

try:
    import redis
except ImportError:
    redis = None

try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
    HAS_TENACITY = True
except ImportError:
    HAS_TENACITY = False


def extract_domain(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.hostname or url.replace("https://", "").replace("http://", "").split("/")[0]


def _format_recon_command(tool: str, target: str, params: dict) -> str:
    """Generate a correct command string for logging based on tool."""
    # Mapping of param keys to command-line flags
    flag_map = {
        "subfinder": {
            "recursive": "-recursive",
            "threads": "-t",
            "timeout": "-timeout",
            "sources": "-sources",
            "resolvers": "-rL",
            "exclude_sources": "-es",
        },
        "httpx": {
            "ports": "-ports",
            "status_code": "-sc",
            "tech_detect": "-td",
            "follow_redirects": "-follow-redirects",
            "threads": "-threads",
            "rate_limit": "-rl",
            "match_codes": "-mc",
            "filter_codes": "-fc",
            "path": "-path",
        },
        "naabu": {
            "ports": "-p",
            "top_ports": "-top-ports 1000",
            "rate": "-rate",
            "timeout": "-timeout",
            "retries": "-retries",
            "interface": "-interface",
            "nmap_cli": "-nmap-cli",
            "exclude_ports": "-exclude-ports",
        },
    }
    # Determine base command
    if tool == "subfinder":
        cmd = f"subfinder -d {target}"
    elif tool == "httpx":
        cmd = f"httpx -u {target}"
    elif tool == "naabu":
        cmd = f"naabu -host {target}"
    else:
        cmd = f"{tool} {target}"
    
    # Add parameters
    for key, value in params.items():
        mapping = flag_map.get(tool, {})
        flag = mapping.get(key)
        if flag is None:
            flag = f"--{key}"
        if tool == "naabu" and key == "ports" and value == "top-1000":
            # Special handling: use -top-ports instead of -p
            cmd += f" -top-ports 1000"
        else:
            if isinstance(value, bool):
                if value:
                    cmd += f" {flag}"
            else:
                cmd += f" {flag} {value}"
    return cmd

# Status constants (UPPERCASE per architecture rule)
STATUS_PENDING = "PENDING"
STATUS_RUNNING = "RUNNING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"
STATUS_PAUSED = "PAUSED"

# Map tool names to TaskType enum values (as strings, uppercase)
TOOL_TO_TASKTYPE = {
    "subfinder": "RECON_SUBDOMAIN",
    "httpx": "RECON_HTTPX",
    "naabu": "RECON_PORTSCAN",
    "nuclei": "RECON_NUCLEI",
    "dirsearch": "RECON_DIRSEARCH",   # if needed
}
STATUS_PARTIAL = "PARTIAL"


class ThreadSafeDeque:
    """Thread-safe bounded deque for events/activities/errors."""

    def __init__(self, maxlen: int = 50):
        self._deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def append(self, item):
        with self._lock:
            self._deque.append(item)

    def get_all(self) -> List:
        with self._lock:
            return list(self._deque)

    def clear(self):
        with self._lock:
            self._deque.clear()

    def __len__(self):
        with self._lock:
            return len(self._deque)

    def remove_by_id(self, task_id: str):
        with self._lock:
            self._deque = deque(
                [item for item in self._deque if item.get("task_id") != task_id],
                maxlen=self._deque.maxlen,
            )


class ScanController:
    """
    Master scan orchestration controller.
    
    Manages the full scan lifecycle: target parsing → task submission →
    result collection → phase progression → report generation.
    """

    # Redis queue names (matching existing modules)
    QUEUE_RECON = "jarvis:queue:recon"
    QUEUE_FUZZER = "jarvis:queue:fuzzer"
    QUEUE_SNIPER = "jarvis:queue:sniper"
    QUEUE_PLAYWRIGHT = "jarvis:queue:playwright"
    QUEUE_RESULTS = "jarvis:results"
    SCAN_STATE_KEY = "jarvis:scan:{scan_id}:state"

    def __init__(
        self,
        config: Dict[str, Any],
        logger=None,
    ):
        self.config = config
        self.logger = logger

        # Scan phases and progression
        self.profile = config.get("profile", "quick") # Assuming profile is part of the config or passed as an argument. For now, defaulting to "quick" if not in config.
        self.phases_config = self.config.get("phases", {})
        self.profile_phases = (
            self.config.get("profiles", {}).get(self.profile, {}).get("phases", [])
        )
        if not self.profile_phases:
            self.profile_phases = ["discovery", "enumeration"] # Default phases
        self.current_phase_index = 0
        self.current_phase = None # As per user instruction.

        # Extract configs from the main config dictionary
        self.redis_config = self.config.get("redis", {})
        self.profile_config = self.config.get("profiles", {})
        self.display_config = self.config.get("display", {})

        # Scan metadata
        self.scan_id: str = ""
        self.targets: List[str] = []
        self.profile_name: str = "quick"
        self.start_time: Optional[float] = None
        self.current_phase: Optional[str] = None
        self.status: str = STATUS_PENDING

        # Thread-safe tracking collections
        self._activities = deque(maxlen=10)
        self._lock = threading.Lock()
        self.events = ThreadSafeDeque(
            maxlen=self.display_config.get("max_events", 50)
        )
        self.errors = ThreadSafeDeque(
            maxlen=self.display_config.get("max_errors", 20)
        )


        # Statistics
        self._stats_lock = threading.Lock()
        self.stats = {
            "tasks_pushed": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "findings_count": 0,
            "ai_calls": 0,
            "rag_snippets": 0,
        }

        # Tool summaries
        self._summaries_lock = threading.Lock()
        self.tool_summaries = {
            "ports_open": [],
            "subdomains": 0,
            "endpoints": 0,
            "payloads_sent": 0,
            "interesting_responses": 0,
            "templates_matched": 0,
            "critical_findings": 0,
            "technologies": [],
        }

        # SPA detection tracking
        self._spa_lock = threading.Lock()
        self._spa_candidates: Dict[str, Dict[str, Any]] = {}  # target -> {technologies, url, etc}

        # Task tracking
        self._tasks_lock = threading.Lock()
        self._pending_tasks: Dict[str, Dict[str, Any]] = {}
        self._completed_tasks: Dict[str, Dict[str, Any]] = {}

        # Redis client
        self._redis: Optional[Any] = None
        self._result_listener_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Callbacks
        self._on_complete_callbacks: List[Callable] = []

    def _log(self, level: str, msg: str):
        if self.logger:
            getattr(self.logger, level, self.logger.info)(msg)

    # ── Redis Connection ──────────────────────────────────────────────

    def _connect_redis(self) -> bool:
        """Establish Redis connection with retries."""
        if redis is None:
            self._add_error("Redis Python package not installed. pip install redis")
            return False

        host = self.redis_config.get("host", "127.0.0.1")
        port = self.redis_config.get("port", 6379)
        db = self.redis_config.get("db", 0)
        password = self.redis_config.get("password")
        timeout = self.redis_config.get("socket_timeout", 5)
        max_retries = self.redis_config.get("max_retries", 3)
        retry_delay = self.redis_config.get("retry_delay", 2)

        for attempt in range(1, max_retries + 1):
            try:
                self._redis = redis.Redis(
                    host=host,
                    port=port,
                    db=db,
                    password=password,
                    socket_timeout=timeout,
                    socket_connect_timeout=timeout,
                    decode_responses=True,
                    retry_on_timeout=True,
                )
                self._redis.ping()
                self._add_event("info", f"Connected to Redis ({host}:{port})")
                return True

            except redis.ConnectionError as e:
                msg = (
                    f"Redis connection failed (attempt {attempt}/{max_retries}): {e}"
                )
                self._log("error", f"[ScanController] {msg}")
                if attempt < max_retries:
                    time.sleep(retry_delay * attempt)
                else:
                    self._add_error(
                        f"Redis not reachable at {host}:{port}. "
                        f"Start Redis or use --manual mode."
                    )
                    return False
            except Exception as e:
                self._add_error(f"Unexpected Redis error: {e}")
                return False
        return False

    # ── Target Parsing ────────────────────────────────────────────────

    def parse_targets(self, target_input: str) -> List[str]:
        """
        Parse target(s) from CLI input.
        
        Accepts:
        - Single URL: "https://example.com"
        - File path: "targets.txt" (one URL per line)
        - Comma-separated: "https://a.com,https://b.com"
        
        Returns list of validated URLs.
        """
        targets = []

        # Check if it's a file
        target_path = Path(target_input)
        if target_path.exists() and target_path.is_file():
            try:
                content = target_path.read_text().strip()
                raw_targets = [line.strip() for line in content.splitlines() if line.strip()]
                self._add_event("info", f"Loaded {len(raw_targets)} target(s) from {target_input}")
            except OSError as e:
                self._add_error(f"Cannot read target file '{target_input}': {e}")
                return []
        elif "," in target_input:
            raw_targets = [t.strip() for t in target_input.split(",") if t.strip()]
        else:
            raw_targets = [target_input.strip()]

        # Validate and normalize URLs
        for raw in raw_targets:
            normalized = self._normalize_url(raw)
            if normalized:
                targets.append(normalized)
            else:
                self._add_error(f"Invalid target URL: '{raw}' – skipping")

        if not targets:
            self._add_error("No valid targets found. Provide a valid URL or file path.")

        return targets

    def _normalize_url(self, url: str) -> Optional[str]:
        """Normalize and validate a URL."""
        url = url.strip()
        if not url:
            return None

        # Skip comments
        if url.startswith("#"):
            return None

        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return None
            # Basic hostname validation
            if not re.match(r'^[a-zA-Z0-9._-]+$', parsed.hostname):
                if not parsed.hostname.startswith('['):  # IPv6
                    return None
            return url
        except Exception:
            return None

    # ── Scan Lifecycle ────────────────────────────────────────────────

    def initialize_scan(
        self,
        target_input: str,
        profile_name: str = "quick",
        scan_id: Optional[str] = None,
    ) -> bool:
        """
        Initialize a new scan.
        
        Returns True if initialization succeeded.
        """
        self.scan_id = scan_id or f"SCAN_{uuid.uuid4().hex[:8].upper()}"
        self.profile_name = profile_name
        self.start_time = time.time()
        self.status = STATUS_RUNNING

        # Parse targets
        self.targets = self.parse_targets(target_input)
        if not self.targets:
            self.status = STATUS_FAILED
            return False

        # Connect Redis
        if not self._connect_redis():
            self.status = STATUS_FAILED
            return False

        self._add_event(
            "info",
            f"Scan {self.scan_id} initialized | Profile: {profile_name} | "
            f"Targets: {len(self.targets)}",
        )

        # Start result listener
        self._start_result_listener()

        return True

    def restore_from_state(self, state: Dict[str, Any]) -> bool:
        """
        Restore scan from saved state for --resume.
        
        Returns True on successful restoration.
        """
        try:
            self.scan_id = state.get("scan_id", self.scan_id)
            self.targets = state.get("targets", [])
            self.profile_name = state.get("profile_name", "quick")
            self.current_phase = state.get("current_phase", "")
            self.stats = state.get("stats", self.stats)
            self.tool_summaries = state.get("tool_summaries", self.tool_summaries)

            # Restore completed tasks (skip them on resume)
            completed = state.get("completed_tasks", {})
            with self._tasks_lock:
                self._completed_tasks = completed

            self.start_time = time.time()  # Reset timer for resumed scan
            self.status = STATUS_RUNNING

            if not self._connect_redis():
                return False

            self._start_result_listener()
            self._add_event("info", f"Scan {self.scan_id} resumed from saved state")
            self._add_event(
                "info",
                f"Skipping {len(completed)} already-completed tasks",
            )
            return True

        except Exception as e:
            self._add_error(f"Failed to restore state: {e}")
            return False

    def run_scan(self) -> bool:
        """
        Execute the scan phases sequentially.
        
        Returns True if scan completed (fully or partially).
        """
        phases = self.profile_phases
        self._add_event("info", f"Starting phased scan: {' → '.join(phases)}")

        for phase in phases:
            if self._stop_event.is_set():
                self.status = STATUS_PAUSED
                self._add_event("warning", "Scan paused by user")
                return True

            self.current_phase = phase
            self._add_event("phase", f"━━━ Phase: {phase.upper()} ━━━")

            try:
                self._run_phase(phase)
                # Wait for phase to complete
                self._wait_for_phase_completion(phase)
            except Exception as e:
                self._add_error(f"Phase '{phase}' failed: {e}")
                continue

        if not self._stop_event.is_set():
            self.current_phase = "reporting"
            self._add_event("phase", "━━━ Phase: REPORTING ━━━")
            self._generate_report()
            self.status = STATUS_COMPLETED
            self._add_event("success", f"Scan {self.scan_id} completed!")

        return True
    def _run_phase(self, phase_name: str):
        """Execute tasks for a given phase."""
        tasks = self._get_phase_tasks(phase_name)
        self._add_event("info", f"Phase '{phase_name}' would run {len(tasks)} tasks: {[t['tool'] for t in tasks]}")

        # Map phase names to existing methods (temporary)
        if phase_name == "discovery":
            self._run_recon_phase(phase_name, tasks)
        elif phase_name == "enumeration":
            # For now, enumeration also uses recon (nuclei, dirsearch)
            self._run_recon_phase(phase_name, tasks)
        elif phase_name == "fuzzing":
            self._run_fuzzing_phase(phase_name, tasks)
        elif phase_name == "exploit":
            self._run_sniper_phase(phase_name, tasks)
        else:
            self._add_error(f"No task method for phase '{phase_name}'")

    # ── Phase Execution ───────────────────────────────────────────────

    def _run_recon_phase(self, phase_name: str, tasks: List[Dict]):
        """Push recon tasks to queue based on given tasks list."""
        for target in self.targets:
            for task in tasks:
                tool = task["tool"]
                params = task.get("params", {})
                task_id = f"{self.scan_id}_{tool}_{uuid.uuid4().hex[:6]}"

                # Skip if already completed (resume scenario)
                with self._tasks_lock:
                    if task_id in self._completed_tasks:
                        continue

                task_type = TOOL_TO_TASKTYPE.get(tool)
                if not task_type:
                    self._add_error(f"Unknown tool '{tool}' – skipping")
                    continue

                # Extract hostname for tools that need domain (subfinder, naabu)
                if tool in ("subfinder", "naabu"):
                    actual_target = extract_domain(target)
                else:
                    actual_target = target

                task_payload = {
                    "task_id": task_id,
                    "scan_id": self.scan_id,
                    "phase": phase_name,
                    "type": task_type,           # ✅ correct type
                    "target": actual_target,      # ✅ hostname for subfinder/naabu
                    "params": params,
                    "status": STATUS_PENDING,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }

                # Add command event for log (using actual_target for display)
                if tool in ("subfinder", "naabu"):
                    display_target = actual_target
                else:
                    display_target = target
                cmd_str = _format_recon_command(tool, display_target, params)
                self._add_event("cmd", cmd_str)

                if self._push_task(self.QUEUE_RECON, task_payload):
                    self._add_activity(task_id, tool, f"scanning {target}")
                    with self._stats_lock:
                        self.stats["tasks_pushed"] += 1

    def _run_fuzzing_phase(self, phase_name: str, tasks: List[Dict]):
        """Push fuzzing tasks based on recon findings."""
        if not tasks:
            self._add_event("info", "No fuzzing tasks defined – skipping")
            return

        # Collect endpoints from recon results
        endpoints = self._get_discovered_endpoints()
        if not endpoints:
            self._add_event("warning", "No endpoints from recon – fuzzing has nothing to test")
            return

        for task in tasks:
            tool = task["tool"]
            params = task.get("params", {})
            vuln_types = params.get("vuln_types", ["xss", "sqli"])
            max_iterations = params.get("max_iterations", 3)

            for endpoint in endpoints:
                for vuln_type in vuln_types:
                    task_id = f"{self.scan_id}_{tool}_{vuln_type}_{uuid.uuid4().hex[:6]}"

                    with self._tasks_lock:
                        if task_id in self._completed_tasks:
                            continue

                    task_payload = {
                        "task_id": task_id,
                        "scan_id": self.scan_id,
                        "phase": phase_name,
                        "tool": tool,
                        "vuln_type": vuln_type,
                        "target": endpoint,
                        "max_iterations": max_iterations,
                        "status": STATUS_PENDING,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }

                    # Add command event for log
                    cmd_str = f"fuzzer --vuln-type {vuln_type} --target {endpoint} --max-iter {max_iterations}"
                    self._add_event("cmd", cmd_str)

                    if self._push_task(self.QUEUE_FUZZER, task_payload):
                        self._add_activity(task_id, f"{tool}:{vuln_type}", f"testing {endpoint}")
                        with self._stats_lock:
                            self.stats["tasks_pushed"] += 1

    def _run_sniper_phase(self, phase_name: str, tasks: List[Dict]):
        """Push sniper tasks based on findings."""
        if not tasks:
            self._add_event("info", "No sniper tasks defined – skipping")
            return

        # Get findings from previous phases
        findings = self._get_current_findings()
        if not findings:
            self._add_event("warning", "No findings for sniper phase – skipping")
            return

        for task in tasks:
            tool = task["tool"]
            params = task.get("params", {})
            feeds = params.get("feeds", ["github", "packetstorm"])
            auto_verify = params.get("auto_verify", True)

            for finding in findings:
                task_id = f"{self.scan_id}_{tool}_{uuid.uuid4().hex[:6]}"

                with self._tasks_lock:
                    if task_id in self._completed_tasks:
                        continue

                task_payload = {
                    "task_id": task_id,
                    "scan_id": self.scan_id,
                    "phase": phase_name,
                    "tool": tool,
                    "finding": finding,
                    "feeds": feeds,
                    "auto_verify": auto_verify,
                    "status": STATUS_PENDING,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }

                # Add command event for log
                feeds_str = ",".join(feeds)
                cmd_str = f"sniper --finding-type {finding.get('type','unknown')} --feeds {feeds_str}"
                self._add_event("cmd", cmd_str)

                # Assuming sniper tasks go to QUEUE_SNIPER (same as before)
                if self._push_task(self.QUEUE_SNIPER, task_payload):
                    self._add_activity(task_id, tool, f"verifying {finding.get('type', 'finding')}")
                    with self._stats_lock:
                        self.stats["tasks_pushed"] += 1

    # ── Task Management ───────────────────────────────────────────────

    def _push_task(self, queue: str, task: Dict[str, Any]) -> bool:
        """Push a task to Redis queue with retry logic."""
        if not self._redis:
            self._add_error(f"Redis not connected – cannot push task {task.get('task_id')}")
            return False

        max_retries = self.redis_config.get("max_retries", 3)
        for attempt in range(1, max_retries + 1):
            try:
                self._redis.rpush(queue, json.dumps(task, default=str))
                with self._tasks_lock:
                    self._pending_tasks[task["task_id"]] = task
                return True
            except Exception as e:
                if attempt == max_retries:
                    self._add_error(
                        f"Failed to push task after {max_retries} retries: {e}"
                    )
                    return False
                time.sleep(self.redis_config.get("retry_delay", 2))

        return False

    def _start_result_listener(self):
        """Start background thread to listen for task results from Redis."""
        self._stop_event.clear()

        def _listen():
            while not self._stop_event.is_set():
                try:
                    if not self._redis:
                        time.sleep(1)
                        continue

                    # BLPOP with timeout so we can check stop_event
                    result = self._redis.blpop(self.QUEUE_RESULTS, timeout=2)
                    if result is None:
                        continue

                    _, raw_data = result
                    self._process_result(json.loads(raw_data))

                except json.JSONDecodeError as e:
                    self._add_error(f"Invalid result JSON: {e}")
                except Exception as e:
                    if not self._stop_event.is_set():
                        self._add_error(f"Result listener error: {e}")
                        time.sleep(2)

        self._result_listener_thread = threading.Thread(
            target=_listen, daemon=True, name="result-listener"
        )
        self._result_listener_thread.start()

    def _process_result(self, result: Dict[str, Any]):
        """Process a completed task result."""
        task_id = result.get("task_id", "unknown")
        status = result.get("status", "UNKNOWN").upper()
        data = result.get("data", {})
        tool = result.get("tool", result.get("phase", "unknown"))

        # AI reasoning
        ai_reason = data.get("ai_reasoning")
        if ai_reason:
            self._add_event("ai", f"AI: {ai_reason[:200]}")

        # Remove from activities
        self.remove_activity(task_id)

        with self._tasks_lock:
            self._pending_tasks.pop(task_id, None)
            self._completed_tasks[task_id] = result

        with self._stats_lock:
            if status == STATUS_COMPLETED:
                self.stats["tasks_completed"] += 1
            else:
                self.stats["tasks_failed"] += 1

            # Count AI/RAG usage
            if data.get("ai_used"):
                self.stats["ai_calls"] += 1
            if data.get("rag_used"):
                self.stats["rag_snippets"] += data.get("rag_snippets", 1)

        # Process findings
        findings = data.get("findings", [])
        if findings:
            with self._stats_lock:
                self.stats["findings_count"] += len(findings)

            for finding in findings:
                severity = finding.get("severity", "info").upper()
                f_type = finding.get("type", "finding")
                location = finding.get("url", finding.get("endpoint", "unknown"))

                if severity in ("CRITICAL", "HIGH"):
                    self._add_event(
                        "critical",
                        f"{severity} {f_type} at {location}",
                    )
                elif severity == "MEDIUM":
                    self._add_event(
                        "warning",
                        f"{severity} {f_type} at {location}",
                    )
                else:
                    self._add_event(
                        "info",
                        f"{f_type} at {location}",
                    )

        # Update tool summaries
        self._update_summaries(tool, data)

        # Detect SPAs and push playwright tasks
        if status == STATUS_COMPLETED:
            # Extract target from result
            target = result.get("target", "")
            if not target:
                # Try to get target from task data
                target = data.get("url", data.get("target", ""))
            if target:
                self._detect_spa_and_push_tasks(tool, data, target)

        # Log completion event
        if status == STATUS_COMPLETED:
            summary = data.get("summary", f"{tool} completed")
            self._add_event("success", summary)
        elif status == STATUS_FAILED:
            error_msg = data.get("error", result.get("error", "Unknown error"))
            self._add_error(f"{tool} failed: {error_msg}")

    def _update_summaries(self, tool: str, data: Dict[str, Any]):
        """Update aggregated tool summaries from result data."""
        with self._summaries_lock:
            # Ports
            ports = data.get("ports", [])
            if ports:
                existing = set(self.tool_summaries["ports_open"])
                existing.update(ports)
                self.tool_summaries["ports_open"] = sorted(existing)

            # Subdomains
            subs = data.get("subdomains", [])
            if subs:
                self.tool_summaries["subdomains"] += len(subs)

            # Endpoints
            eps = data.get("endpoints", [])
            if eps:
                self.tool_summaries["endpoints"] += len(eps)
                for ep in eps[:3]:  # Log first few
                    url = ep if isinstance(ep, str) else ep.get("url", str(ep))
                    status_code = ep.get("status", "") if isinstance(ep, dict) else ""
                    self._add_event(
                        "discovery",
                        f"Endpoint: {url}" + (f" ({status_code})" if status_code else ""),
                    )

            # Technologies
            techs = data.get("technologies", [])
            if techs:
                existing = set(self.tool_summaries["technologies"])
                existing.update(techs)
                self.tool_summaries["technologies"] = list(existing)
                self._add_event("info", f"Tech: {', '.join(techs)}")

            # Fuzzing stats
            self.tool_summaries["payloads_sent"] += data.get("payloads_sent", 0)
            self.tool_summaries["interesting_responses"] += data.get(
                "interesting_responses", 0
            )

            # Nuclei/template stats
            self.tool_summaries["templates_matched"] += data.get(
                "templates_matched", 0
            )
            critical_count = sum(
                1
                for f in data.get("findings", [])
                if f.get("severity", "").upper() in ("CRITICAL", "HIGH")
            )
            self.tool_summaries["critical_findings"] += critical_count

    def _detect_spa_and_push_tasks(self, tool: str, data: Dict[str, Any], target: str):
        """Detect Single Page Applications from httpx tech_detect results and push playwright tasks."""
        if tool != "httpx":
            return
        
        techs = data.get("technologies", [])
        if not techs:
            return
        
        # Get playwright config
        playwright_config = self.config.get("playwright", {})
        spa_frameworks = playwright_config.get("spa_frameworks", ["react", "vue", "angular", "next.js", "nuxt", "svelte", "ember"])
        max_targets = playwright_config.get("max_targets", 5)
        
        # Check if any SPA framework detected
        detected_frameworks = []
        for tech in techs:
            tech_lower = tech.lower()
            for framework in spa_frameworks:
                if framework.lower() in tech_lower:
                    detected_frameworks.append(framework)
                    break
        
        if not detected_frameworks:
            return
        
        # Store SPA candidate
        with self._spa_lock:
            # Limit number of SPA targets
            if len(self._spa_candidates) >= max_targets:
                self._add_event("info", f"SPA detection limit reached ({max_targets}), skipping {target}")
                return
            
            self._spa_candidates[target] = {
                "technologies": detected_frameworks,
                "url": target,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
            
        self._add_event("info", f"SPA detected: {target} ({', '.join(detected_frameworks)})")
        
        # Push playwright task
        self._push_playwright_task(target)

    def _push_playwright_task(self, target: str):
        """Push a playwright rendering task to the playwright queue."""
        playwright_config = self.config.get("playwright", {})
        
        task_id = f"{self.scan_id}_playwright_{uuid.uuid4().hex[:6]}"
        
        task_payload = {
            "task_id": task_id,
            "scan_id": self.scan_id,
            "phase": "playwright",
            "type": "PLAYWRIGHT_RENDER",
            "target": target,
            "params": {
                "extract_forms": playwright_config.get("extract_forms", True),
                "max_depth": playwright_config.get("max_depth", 1),
                "timeout": 30,
            },
            "status": STATUS_PENDING,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        
        if self._push_task(self.QUEUE_PLAYWRIGHT, task_payload):
            self._add_activity(task_id, "playwright", f"rendering {target}")
            with self._stats_lock:
                self.stats["tasks_pushed"] += 1
            self._add_event("cmd", f"playwright render {target}")
        else:
            self._add_error(f"Failed to push playwright task for {target}")

    def _wait_for_phase_completion(self, phase: str, timeout: int = 600):
        """Wait until all tasks for current phase are completed."""
        deadline = time.time() + timeout
        check_interval = 2

        while time.time() < deadline:
            if self._stop_event.is_set():
                return

            with self._tasks_lock:
                pending_for_phase = [
                    t for t in self._pending_tasks.values()
                    if t.get("phase") == phase
                ]

            if not pending_for_phase:
                self._add_event("success", f"Phase '{phase}' completed")
                return

            time.sleep(check_interval)

        # Timeout
        with self._tasks_lock:
            remaining = len([
                t for t in self._pending_tasks.values()
                if t.get("phase") == phase
            ])
        if remaining > 0:
            self._add_event(
                "warning",
                f"Phase '{phase}' timed out with {remaining} pending tasks",
            )

    def _get_discovered_endpoints(self) -> List[str]:
        """Get endpoints discovered during recon for fuzzing."""
        endpoints = []
        with self._tasks_lock:
            for result in self._completed_tasks.values():
                data = result.get("data", {})
                eps = data.get("endpoints", [])
                for ep in eps:
                    url = ep if isinstance(ep, str) else ep.get("url", str(ep))
                    if url:
                        endpoints.append(url)

        # Fallback: use original targets if no endpoints found
        if not endpoints:
            endpoints = list(self.targets)

        return endpoints

    def _get_current_findings(self) -> List[Dict[str, Any]]:
        """Get findings accumulated so far for sniper phase."""
        findings = []
        with self._tasks_lock:
            for result in self._completed_tasks.values():
                data = result.get("data", {})
                findings.extend(data.get("findings", []))
        return findings

    def _generate_report(self):
        """Trigger report generation."""
        try:
            report_data = {
                "scan_id": self.scan_id,
                "targets": self.targets,
                "profile": self.profile_name,
                "stats": dict(self.stats),
                "tool_summaries": dict(self.tool_summaries),
                "findings": self._get_current_findings(),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "data": {  # Required field
                    "findings": self._get_current_findings(),
                    "stats": dict(self.stats),
                },
            }

            # Try to push to reporting queue
            if self._redis:
                try:
                    self._redis.rpush(
                        "jarvis:queue:reporting",
                        json.dumps(report_data, default=str),
                    )
                    self._add_event("success", "Report task queued")
                except Exception as e:
                    self._add_error(f"Failed to queue report: {e}")
                    # Fallback: save JSON dump locally
                    self._save_fallback_report(report_data)
            else:
                self._save_fallback_report(report_data)

        except Exception as e:
            self._add_error(f"Report generation failed: {e}")
            self._save_fallback_report({"error": str(e), "scan_id": self.scan_id})

    def _save_fallback_report(self, data: Dict[str, Any]):
        """Save report as JSON file when queue/template fails."""
        try:
            report_dir = Path("reports")
            report_dir.mkdir(parents=True, exist_ok=True)
            filepath = report_dir / f"{self.scan_id}_report.json"
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2, default=str)
            self._add_event("info", f"Fallback report saved: {filepath}")
        except OSError as e:
            self._add_error(f"Fallback report save failed: {e}")

    # ── Event/Activity Helpers ────────────────────────────────────────

    def _add_event(self, event_type: str, message: str):
        """Add an event to the live feed."""
        self.events.append({
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "type": event_type,
            "message": message,
        })

    def _add_error(self, message: str):
        """Add an error to the error panel."""
        self.errors.append({
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "message": message,
        })
        self._log("error", f"[ScanController] {message}")

    def add_activity(self, task_id: str, tool: str, description: str):
        """Add a current activity in a thread-safe manner."""
        with self._lock:
            self._activities.append({
                "task_id": task_id,
                "tool": tool,
                "description": description,
                "started_at": time.time(),
            })

    def remove_activity(self, task_id: str):
        """Remove a completed activity by task_id in a thread-safe manner."""
        with self._lock:
            self._activities = deque(
                [item for item in self._activities if item.get("task_id") != task_id],
                maxlen=self._activities.maxlen,
            )

    def get_activities(self) -> List[Dict[str, Any]]:
        """Get all current activities in a thread-safe manner."""
        with self._lock:
            return list(self._activities)

    def _add_activity(self, task_id: str, tool: str, description: str):
        """Add a current activity."""
        self.add_activity(task_id, tool, description)


    # ── Queue Status ──────────────────────────────────────────────────

    def get_queue_lengths(self) -> Dict[str, int]:
        """Get current Redis queue lengths."""
        if not self._redis:
            return {}
        try:
            return {
                "recon": self._redis.llen(self.QUEUE_RECON),
                "fuzzer": self._redis.llen(self.QUEUE_FUZZER),
                "sniper": self._redis.llen(self.QUEUE_SNIPER),
                "results": self._redis.llen(self.QUEUE_RESULTS),
            }
        except Exception:
            return {}

    # ── State Export ──────────────────────────────────────────────────

    def get_full_state(self) -> Dict[str, Any]:
        """Export full scan state for saving/resume."""
        with self._tasks_lock:
            completed = dict(self._completed_tasks)
            pending = dict(self._pending_tasks)

        return {
            "scan_id": self.scan_id,
            "targets": self.targets,
            "profile_name": self.profile_name,
            "current_phase": self.current_phase,
            "status": self.status,
            "stats": dict(self.stats),
            "tool_summaries": dict(self.tool_summaries),
            "completed_tasks": completed,
            "pending_tasks": pending,
            "events": self.events.get_all(),
            "errors": self.errors.get_all(),
        }

    def get_elapsed_time(self) -> str:
        """Get elapsed time as formatted string."""
        if not self.start_time:
            return "00:00"
        elapsed = int(time.time() - self.start_time)
        minutes, seconds = divmod(elapsed, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"

    def _get_phase_tasks(self, phase_name):
        phase_cfg = self.phases_config.get(phase_name, {})
        return phase_cfg.get("tasks", [])

    # ── Shutdown ──────────────────────────────────────────────────────

    def stop(self):
        """Signal stop to all background threads."""
        self._stop_event.set()
        if self._result_listener_thread and self._result_listener_thread.is_alive():
            self._result_listener_thread.join(timeout=5)
        if self._redis:
            try:
                self._redis.close()
            except Exception:
                pass
