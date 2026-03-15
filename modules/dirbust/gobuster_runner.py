"""
Gobuster Runner (Fallback)
===========================
Provides the same interface as ffuf_runner but uses gobuster.
Only used when ffuf is unavailable.
Parses gobuster's text output via regex.
"""

import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from modules.dirbust.ffuf_runner import (
    Finding,
    FfufResult,  # Reuse the same result dataclass
    ToolMissingError,
)

# ── Logging Setup ────────────────────────────────────────────────────
try:
    from shared.logger import get_logger
    logger = get_logger("dirbust.gobuster_runner")
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"timestamp":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","message":"%(message)s"}'
    )
    logger = logging.getLogger("dirbust.gobuster_runner")


# Regex for gobuster output lines:
# /admin                (Status: 200) [Size: 1234]
# /images               (Status: 301) [Size: 0] [--> /images/]
GOBUSTER_LINE_RE = re.compile(
    r"^(/\S*)\s+"
    r"\(Status:\s*(\d+)\)\s+"
    r"\[Size:\s*(\d+)\]"
    r"(?:\s*\[--> (.+?)\])?"
)


def check_gobuster(binary_path: str = "gobuster") -> Tuple[bool, str]:
    """Check if gobuster binary is available."""
    resolved = shutil.which(binary_path)
    if not resolved:
        return False, f"Binary '{binary_path}' not found in PATH"

    try:
        proc = subprocess.run(
            [resolved, "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version_line = (proc.stdout.strip() or proc.stderr.strip() or "unknown")
        return True, version_line
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"Binary found at '{resolved}' but failed to execute: {e}"


def run_gobuster(
    target: str,
    wordlist: str,
    extensions: Optional[List[str]] = None,
    threads: int = 40,
    delay: float = 0.0,
    recursive: bool = False,
    depth: int = 1,
    timeout: int = 300,
    binary_path: str = "gobuster",
    extra_flags: Optional[List[str]] = None,
) -> FfufResult:
    """
    Execute gobuster and parse its text output.
    Returns FfufResult for interface compatibility with the worker.

    Raises:
        ToolMissingError: If gobuster binary is not available.
    """
    resolved = shutil.which(binary_path)
    if not resolved:
        raise ToolMissingError("gobuster", binary_path)

    wl_path = Path(wordlist)
    if not wl_path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {wordlist}")

    target = target.rstrip("/")

    # ── Build command ────────────────────────────────────────────────
    cmd: List[str] = [
        resolved,
        "dir",
        "-u", target,
        "-w", str(wl_path),
        "-t", str(threads),
        "--no-progress",              # suppress progress bar
        "--no-color",                 # no ANSI codes
        "-q",                         # quiet mode (less noise)
        "-e",                         # expanded URLs in output
    ]

    # Extensions
    if extensions:
        ext_str = ",".join(e.lstrip('.') for e in extensions)
        cmd.extend(["-x", ext_str])

    # Delay (gobuster uses --delay with duration string)
    if delay and delay > 0:
        delay_ms = int(delay * 1000)
        cmd.extend(["--delay", f"{delay_ms}ms"])

    # Note: gobuster does not support recursive natively in older versions
    # We log a warning and skip the flag
    if recursive:
        logger.warning(
            "Gobuster fallback: recursion may not be supported in all versions. "
            "Consider installing ffuf for full recursive support."
        )

    # Timeout
    cmd.extend(["--timeout", f"{min(timeout, 30)}s"])  # per-request timeout

    if extra_flags:
        cmd.extend(extra_flags)

    command_str = " ".join(cmd)
    logger.info("Executing gobuster (fallback)", extra={"command": command_str})

    # ── Execute ──────────────────────────────────────────────────────
    result = FfufResult(command=command_str)
    start_time = time.monotonic()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        findings: List[Finding] = []
        unparsed = 0

        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            finding = _parse_gobuster_line(line, target)
            if finding:
                findings.append(finding)
            elif not line.startswith("=") and "Gobuster" not in line:
                unparsed += 1
                if unparsed <= 5:
                    logger.debug(
                        "Unrecognised gobuster output line",
                        extra={"line": line[:200]}
                    )

        remaining_timeout = max(1, timeout - int(time.monotonic() - start_time))
        try:
            proc.wait(timeout=remaining_timeout)
        except subprocess.TimeoutExpired:
            logger.warning("gobuster process timed out, killing")
            proc.kill()
            proc.wait(timeout=5)

        stderr_output = proc.stderr.read() if proc.stderr else ""

        result.findings = findings
        result.return_code = proc.returncode or 0
        result.stderr_output = stderr_output
        result.raw_unparsed_lines = unparsed
        result.elapsed_seconds = round(time.monotonic() - start_time, 3)
        result.total_requests = len(findings)  # gobuster doesn't report total
        result.errors = 0

        logger.info(
            "gobuster completed",
            extra={
                "findings": len(findings),
                "elapsed": result.elapsed_seconds,
                "return_code": result.return_code,
            }
        )

        return result

    except OSError as e:
        result.elapsed_seconds = round(time.monotonic() - start_time, 3)
        result.errors = 1
        result.stderr_output = str(e)
        logger.error("gobuster execution failed", extra={"error": str(e)})
        raise


def _parse_gobuster_line(line: str, target: str) -> Optional[Finding]:
    """
    Parse a single gobuster output line into a Finding.

    Expected formats:
        http://example.com/admin                (Status: 200) [Size: 1234]
        http://example.com/images               (Status: 301) [Size: 0] [--> /images/]
    """
    # With -e flag, gobuster outputs full URLs
    # Try regex on the line
    # Adjust regex for full URL output
    full_url_re = re.compile(
        r"^(\S+)\s+"
        r"\(Status:\s*(\d+)\)\s+"
        r"\[Size:\s*(\d+)\]"
        r"(?:\s*\[--> (.+?)\])?"
    )

    match = full_url_re.match(line)
    if not match:
        # Try without expanded URL
        match = GOBUSTER_LINE_RE.match(line)
        if not match:
            return None
        url = f"{target}{match.group(1)}"
        status = int(match.group(2))
        size = int(match.group(3))
        redirect = match.group(4) or ""
        input_word = match.group(1).lstrip("/")
    else:
        url = match.group(1)
        status = int(match.group(2))
        size = int(match.group(3))
        redirect = match.group(4) or ""
        # Extract input word from URL
        input_word = url.replace(target, "").lstrip("/")

    return Finding(
        url=url,
        status_code=status,
        content_length=size,
        redirect_location=redirect,
        input_word=input_word,
    )
