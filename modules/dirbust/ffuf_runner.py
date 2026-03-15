"""
ffuf Runner
===========
Wraps the ffuf binary for directory/file brute-forcing.
- Builds command with correct flags.
- Parses JSON output (one JSON object per line from stdout).
- Returns structured findings and stats.
- Raises ToolMissingError if ffuf binary is not available.
"""

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Logging Setup ────────────────────────────────────────────────────
try:
    from shared.logger import get_logger
    logger = get_logger("dirbust.ffuf_runner")
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"timestamp":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","message":"%(message)s"}'
    )
    logger = logging.getLogger("dirbust.ffuf_runner")


class ToolMissingError(Exception):
    """Raised when a required tool binary is not found on the system."""
    def __init__(self, tool_name: str, searched_path: str):
        self.tool_name = tool_name
        self.searched_path = searched_path
        super().__init__(
            f"Tool '{tool_name}' not found. Searched: '{searched_path}'. "
            f"Install it or provide the full path in config.yaml."
        )


@dataclass
class Finding:
    """A single discovered directory/file."""
    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    redirect_location: str = ""
    input_word: str = ""
    lines: int = 0
    words: int = 0
    duration_ms: float = 0.0
    host: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "redirect_location": self.redirect_location,
            "input_word": self.input_word,
            "lines": self.lines,
            "words": self.words,
            "duration_ms": self.duration_ms,
            "host": self.host,
        }


@dataclass
class FfufResult:
    """Aggregated result from an ffuf run."""
    findings: List[Finding] = field(default_factory=list)
    total_requests: int = 0
    errors: int = 0
    elapsed_seconds: float = 0.0
    command: str = ""
    return_code: int = 0
    stderr_output: str = ""
    raw_unparsed_lines: int = 0  # lines that failed JSON parsing

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "stats": {
                "total_requests": self.total_requests,
                "total_findings": len(self.findings),
                "errors": self.errors,
                "elapsed_seconds": self.elapsed_seconds,
                "raw_unparsed_lines": self.raw_unparsed_lines,
            },
            "meta": {
                "command": self.command,
                "return_code": self.return_code,
            }
        }


def check_ffuf(binary_path: str = "ffuf") -> Tuple[bool, str]:
    """
    Check if ffuf binary is available and return its version.

    Returns:
        Tuple of (available: bool, version_or_error: str)
    """
    resolved = shutil.which(binary_path)
    if not resolved:
        return False, f"Binary '{binary_path}' not found in PATH"

    try:
        proc = subprocess.run(
            [resolved, "-V"],
            capture_output=True,
            text=True,
            timeout=10
        )
        version_line = (proc.stdout.strip() or proc.stderr.strip() or "unknown")
        return True, version_line
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"Binary found at '{resolved}' but failed to execute: {e}"


def run_ffuf(
    target: str,
    wordlist: str,
    extensions: Optional[List[str]] = None,
    threads: int = 40,
    delay: float = 0.0,
    recursive: bool = False,
    depth: int = 1,
    timeout: int = 300,
    binary_path: str = "ffuf",
    extra_flags: Optional[List[str]] = None,
) -> FfufResult:
    """
    Execute ffuf and parse its JSON output.

    Args:
        target: Base URL (e.g., https://example.com).
        wordlist: Path to wordlist file.
        extensions: File extensions to fuzz (without dots).
        threads: Number of concurrent threads.
        delay: Delay between requests in seconds.
        recursive: Enable recursive scanning.
        depth: Maximum recursion depth.
        timeout: Overall timeout in seconds.
        binary_path: Path or name of ffuf binary.
        extra_flags: Additional CLI flags to pass to ffuf.

    Returns:
        FfufResult with findings and stats.

    Raises:
        ToolMissingError: If ffuf binary is not available.
    """
    # ── Validate binary ──────────────────────────────────────────────
    resolved = shutil.which(binary_path)
    if not resolved:
        raise ToolMissingError("ffuf", binary_path)

    # ── Validate wordlist ────────────────────────────────────────────
    wl_path = Path(wordlist)
    if not wl_path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {wordlist}")

    # ── Normalise target URL ─────────────────────────────────────────
    target = target.rstrip("/")

    # ── Build command ────────────────────────────────────────────────
    cmd: List[str] = [
        resolved,
        "-u", f"{target}/FUZZ",
        "-w", str(wl_path),
        "-t", str(threads),
        "-json",                  # JSON output to stdout
        "-noninteractive",        # no progress bars / interactive UI
        "-mc", "all",             # match all status codes, we filter later
        "-fc", "404",             # filter 404s by default to reduce noise
    ]

    # Extensions
    if extensions:
        ext_str = ",".join(f".{e.lstrip('.')}" for e in extensions)
        cmd.extend(["-e", ext_str])

    # Delay / rate limiting
    if delay and delay > 0:
        cmd.extend(["-p", str(delay)])

    # Recursion
    if recursive:
        cmd.append("-recursion")
        cmd.extend(["-recursion-depth", str(depth)])

    # Extra flags
    if extra_flags:
        cmd.extend(extra_flags)

    command_str = " ".join(cmd)
    logger.info("Executing ffuf", extra={"command": command_str})

    # ── Execute ──────────────────────────────────────────────────────
    result = FfufResult(command=command_str)
    start_time = time.monotonic()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # line-buffered
        )

        # ── Stream and parse stdout line by line ─────────────────────
        findings: List[Finding] = []
        unparsed = 0

        assert proc.stdout is not None  # type guard
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
                finding = _parse_ffuf_json_entry(entry, target)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                unparsed += 1
                if unparsed <= 5:
                    logger.warning(
                        "Malformed JSON line from ffuf (skipping)",
                        extra={"line_preview": line[:200], "unparsed_total": unparsed}
                    )

        # Wait for process to finish (respect timeout)
        remaining_timeout = max(1, timeout - int(time.monotonic() - start_time))
        try:
            proc.wait(timeout=remaining_timeout)
        except subprocess.TimeoutExpired:
            logger.warning("ffuf process timed out, killing", extra={"timeout": timeout})
            proc.kill()
            proc.wait(timeout=5)

        stderr_output = proc.stderr.read() if proc.stderr else ""

        result.findings = findings
        result.return_code = proc.returncode or 0
        result.stderr_output = stderr_output
        result.raw_unparsed_lines = unparsed
        result.elapsed_seconds = round(time.monotonic() - start_time, 3)

        # ── Extract stats from stderr if available ───────────────────
        result.total_requests = _extract_request_count(stderr_output, len(findings))
        result.errors = _extract_error_count(stderr_output)

        logger.info(
            "ffuf completed",
            extra={
                "findings": len(findings),
                "elapsed": result.elapsed_seconds,
                "return_code": result.return_code,
                "unparsed_lines": unparsed,
            }
        )

        return result

    except OSError as e:
        result.elapsed_seconds = round(time.monotonic() - start_time, 3)
        result.errors = 1
        result.stderr_output = str(e)
        logger.error("ffuf execution failed", extra={"error": str(e)})
        raise


def _parse_ffuf_json_entry(entry: dict, target: str) -> Optional[Finding]:
    """
    Parse a single ffuf JSON output entry into a Finding.

    ffuf JSON output structure (per result):
    {
        "input": {"FUZZ": "admin"},
        "position": 42,
        "status": 200,
        "length": 1234,
        "words": 50,
        "lines": 20,
        "content-type": "text/html",
        "redirectlocation": "",
        "url": "http://example.com/admin",
        "resultFile": "",
        "host": "example.com",
        "duration": 123456789   # nanoseconds
    }
    """
    # ffuf may output config/status lines as JSON too; skip non-result entries
    if "status" not in entry or "url" not in entry:
        return None

    try:
        input_data = entry.get("input", {})
        input_word = ""
        if isinstance(input_data, dict):
            input_word = input_data.get("FUZZ", "")
        elif isinstance(input_data, str):
            input_word = input_data

        duration_ns = entry.get("duration", 0)
        duration_ms = duration_ns / 1_000_000 if duration_ns else 0.0

        return Finding(
            url=entry.get("url", ""),
            status_code=int(entry.get("status", 0)),
            content_length=int(entry.get("length", 0)),
            content_type=entry.get("content-type", ""),
            redirect_location=entry.get("redirectlocation", ""),
            input_word=input_word,
            lines=int(entry.get("lines", 0)),
            words=int(entry.get("words", 0)),
            duration_ms=round(duration_ms, 2),
            host=entry.get("host", ""),
        )
    except (ValueError, TypeError, KeyError) as e:
        logger.warning(
            "Failed to parse ffuf entry",
            extra={"error": str(e), "entry_keys": list(entry.keys())}
        )
        return None


def _extract_request_count(stderr: str, finding_count: int) -> int:
    """Extract total requests from ffuf stderr summary. Falls back to finding_count."""
    import re
    # ffuf stderr example: ":: Progress: [4614/4614] :: Job [1/1] :: ..."
    match = re.search(r"Progress:\s*\[\d+/(\d+)\]", stderr)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            pass
    return finding_count


def _extract_error_count(stderr: str) -> int:
    """Extract error count from ffuf stderr. Returns 0 if not found."""
    import re
    # ffuf stderr: ":: Errors: 3 ::"
    match = re.search(r"Errors:\s*(\d+)", stderr)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            pass
    return 0
