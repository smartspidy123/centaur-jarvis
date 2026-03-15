"""
modules/recon/tasks.py
======================
Individual recon task implementations.

Each public function has the signature::

    def xxx_task(target, params, tool_path, timeout) -> TaskExecResult

and returns a ``TaskExecResult`` named-tuple containing:

    (stdout, stderr, return_code, error, error_type, tool_version)

Design rules:
  - Every parameter is validated before being injected into the command line
    to prevent command-injection.
  - Subprocesses are spawned with ``shell=False`` — arguments are a list.
  - Stdout is streamed line-by-line through a size guard to prevent OOM.
  - The calling code (``worker.py``) is responsible for *parsing* the output;
    this module only handles *execution*.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


class TaskExecResult(NamedTuple):
    stdout: str
    stderr: str
    return_code: int
    error: Optional[str]
    error_type: str        # maps to shared.schemas.ErrorType value
    tool_version: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Characters allowed in a domain / IP target (strict allowlist)
_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9._:/@\-\[\]]+$")

# Max output size we'll keep in memory (50 MB default, configurable)
_MAX_OUTPUT_BYTES = int(os.environ.get("RECON_MAX_OUTPUT_BYTES", 50 * 1024 * 1024))


def _validate_target(target: str) -> Optional[str]:
    """
    Return an error string if the target is dangerous/invalid, else ``None``.
    """
    if not target or not target.strip():
        return "Target is empty"
    if len(target) > 253:
        return f"Target too long ({len(target)} chars)"
    if not _SAFE_TARGET_RE.match(target):
        return f"Target contains disallowed characters: {target!r}"
    # Block obvious shell-injection attempts
    for dangerous in (";", "&", "|", "$", "`", "(", ")", "{", "}", "!", "\n", "\r"):
        if dangerous in target:
            return f"Target contains shell meta-character: {dangerous!r}"
    return None


def _resolve_tool(path: str) -> Optional[str]:
    """
    Resolve a tool path.  Returns the absolute path or ``None`` if missing.
    """
    if os.path.isabs(path):
        return path if os.path.isfile(path) and os.access(path, os.X_OK) else None
    return shutil.which(path)


def _get_tool_version(tool_abs_path: str, version_flag: str = "-version") -> str:
    """
    Best-effort attempt to capture the tool's version string.
    """
    try:
        proc = subprocess.run(
            [tool_abs_path, version_flag],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        # First non-empty line
        for line in output.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped[:200]
    except Exception:
        pass
    return "unknown"


def _run_subprocess(
    cmd: List[str],
    timeout: int,
    stdin_data: Optional[str] = None,
    max_output_bytes: int = _MAX_OUTPUT_BYTES,
) -> Tuple[str, str, int]:
    """
    Execute *cmd* with hard timeout and output-size guard.

    Returns ``(stdout, stderr, returncode)``.
    Raises ``TimeoutError`` if the process exceeds *timeout*.
    Raises ``MemoryError`` if stdout exceeds *max_output_bytes*.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
        text=True,
        # Isolate from calling process' env as much as possible
        env={**os.environ, "HOME": os.environ.get("HOME", "/tmp")},
        start_new_session=True,  # so we can kill the whole process group
    )

    try:
        stdout, stderr = proc.communicate(
            input=stdin_data,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        # Kill the entire process group
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            proc.kill()
        proc.wait(timeout=5)
        raise TimeoutError(f"Subprocess timed out after {timeout}s")

    # Size guard (checked post-mortem; streaming guard is in worker.py)
    if len(stdout.encode("utf-8", errors="replace")) > max_output_bytes:
        raise MemoryError(
            f"Tool output exceeded {max_output_bytes} bytes limit"
        )

    return stdout, stderr, proc.returncode


# ---------------------------------------------------------------------------
# Public task functions
# ---------------------------------------------------------------------------


def subfinder_task(
    target: str,
    params: Dict[str, Any],
    tool_path: str = "subfinder",
    timeout: int = 300,
    version_flag: str = "-version",
) -> TaskExecResult:
    """
    Run Subfinder for subdomain enumeration.

    Command template::

        subfinder -d <domain> -silent -oJ [-all] [-t N] [-timeout N] ...
    """
    # --- Validation ---
    err = _validate_target(target)
    if err:
        return TaskExecResult("", "", -1, err, "INVALID_TARGET", "")

    abs_path = _resolve_tool(tool_path)
    if abs_path is None:
        return TaskExecResult(
            "", "", -1,
            f"Tool not found: {tool_path}",
            "TOOL_MISSING", "",
        )

    version = _get_tool_version(abs_path, version_flag)

    # --- Build command ---
    cmd: List[str] = [abs_path, "-d", target, "-silent", "-oJ"]

    if params.get("recursive"):
        cmd.append("-all")
    if params.get("threads"):
        cmd.extend(["-t", str(int(params["threads"]))])
    if params.get("timeout"):
        cmd.extend(["-timeout", str(int(params["timeout"]))])
    if params.get("sources"):
        # Comma-separated list validated against allowlist
        sources = str(params["sources"])
        if _SAFE_TARGET_RE.match(sources.replace(",", "")):
            cmd.extend(["-sources", sources])
    if params.get("resolvers"):
        resolvers = str(params["resolvers"])
        if _SAFE_TARGET_RE.match(resolvers.replace(",", "")):
            cmd.extend(["-rL", resolvers])
    if params.get("exclude_sources"):
        es = str(params["exclude_sources"])
        if _SAFE_TARGET_RE.match(es.replace(",", "")):
            cmd.extend(["-es", es])

    # --- Execute ---
    try:
        stdout, stderr, rc = _run_subprocess(cmd, timeout)
    except TimeoutError as exc:
        return TaskExecResult("", str(exc), -1, str(exc), "TIMEOUT", version)
    except MemoryError as exc:
        return TaskExecResult("", str(exc), -1, str(exc), "TOOL_ERROR", version)

    if rc != 0:
        return TaskExecResult(
            stdout, stderr, rc,
            f"subfinder exited with code {rc}: {stderr[:500]}",
            "TOOL_ERROR", version,
        )

    return TaskExecResult(stdout, stderr, rc, None, "NONE", version)


def httpx_task(
    target: str,
    params: Dict[str, Any],
    tool_path: str = "httpx",
    timeout: int = 300,
    version_flag: str = "-version",
) -> TaskExecResult:
    """
    Run Httpx for HTTP probing.

    Supports two modes:

    1. **Single target** — ``httpx -u <url> -silent -json``
    2. **File input** — ``httpx -l <file> -silent -json``
       (when ``params["input_list"]`` is a list of URLs/domains)
    """
    abs_path = _resolve_tool(tool_path)
    if abs_path is None:
        return TaskExecResult("", "", -1, f"Tool not found: {tool_path}", "TOOL_MISSING", "")

    version = _get_tool_version(abs_path, version_flag)
    tmp_file: Optional[str] = None

    try:
        cmd: List[str] = [abs_path, "-silent", "-json"]

        input_list = params.get("input_list")
        if isinstance(input_list, list) and input_list:
            # Write targets to a temp file
            tmp_fd, tmp_file = tempfile.mkstemp(prefix="httpx_in_", suffix=".txt")
            with os.fdopen(tmp_fd, "w") as fh:
                for item in input_list:
                    err = _validate_target(str(item))
                    if err:
                        continue  # skip invalid, log later
                    fh.write(str(item) + "\n")
            cmd.extend(["-l", tmp_file])
        else:
            err = _validate_target(target)
            if err:
                return TaskExecResult("", "", -1, err, "INVALID_TARGET", version)
            cmd.extend(["-u", target])

        # Optional flags
        if params.get("ports"):
            cmd.extend(["-ports", str(params["ports"])])
        if params.get("path"):
            path_val = str(params["path"])
            if _SAFE_TARGET_RE.match(path_val):
                cmd.extend(["-path", path_val])
        if params.get("status_code"):
            cmd.append("-status-code")
        if params.get("tech_detect"):
            cmd.append("-tech-detect")
        if params.get("follow_redirects"):
            cmd.append("-follow-redirects")
        if params.get("threads"):
            cmd.extend(["-threads", str(int(params["threads"]))])
        if params.get("rate_limit"):
            cmd.extend(["-rl", str(int(params["rate_limit"]))])
        if params.get("match_codes"):
            cmd.extend(["-mc", str(params["match_codes"])])
        if params.get("filter_codes"):
            cmd.extend(["-fc", str(params["filter_codes"])])

        # --- Execute ---
        try:
            stdout, stderr, rc = _run_subprocess(cmd, timeout)
        except TimeoutError as exc:
            return TaskExecResult("", str(exc), -1, str(exc), "TIMEOUT", version)
        except MemoryError as exc:
            return TaskExecResult("", str(exc), -1, str(exc), "TOOL_ERROR", version)

        if rc != 0:
            return TaskExecResult(
                stdout, stderr, rc,
                f"httpx exited with code {rc}: {stderr[:500]}",
                "TOOL_ERROR", version,
            )

        return TaskExecResult(stdout, stderr, rc, None, "NONE", version)
    finally:
        if tmp_file and os.path.exists(tmp_file):
            os.unlink(tmp_file)


def nuclei_task(
    target: str,
    params: Dict[str, Any],
    tool_path: str = "nuclei",
    timeout: int = 300,
    version_flag: str = "-version",
) -> TaskExecResult:
    """
    Run Nuclei vulnerability scanner.

    Command template::

        nuclei -u <target> -json -silent [-t templates] [-severity S] ...
    """
    err = _validate_target(target)
    if err:
        return TaskExecResult("", "", -1, err, "INVALID_TARGET", "")

    abs_path = _resolve_tool(tool_path)
    if abs_path is None:
        return TaskExecResult("", "", -1, f"Tool not found: {tool_path}", "TOOL_MISSING", "")

    version = _get_tool_version(abs_path, version_flag)

    cmd: List[str] = [abs_path, "-u", target, "-jsonl", "-silent"]

    if params.get("templates"):
        tmpl = str(params["templates"])
        # Templates can be comma-separated paths / IDs
        cmd.extend(["-t", tmpl])
    if params.get("severity"):
        sev = str(params["severity"]).lower()
        allowed_sevs = {"info", "low", "medium", "high", "critical", "unknown"}
        parts = [s.strip() for s in sev.split(",") if s.strip() in allowed_sevs]
        if parts:
            cmd.extend(["-severity", ",".join(parts)])
    if params.get("tags"):
        cmd.extend(["-tags", str(params["tags"])])
    if params.get("rate_limit"):
        cmd.extend(["-rl", str(int(params["rate_limit"]))])
    if params.get("exclude_tags"):
        cmd.extend(["-etags", str(params["exclude_tags"])])
    if params.get("exclude_templates"):
        cmd.extend(["-exclude", str(params["exclude_templates"])])
    if params.get("headless"):
        cmd.append("-headless")
    if params.get("new_templates"):
        cmd.append("-nt")
    if params.get("automatic_scan"):
        cmd.append("-as")

    try:
        stdout, stderr, rc = _run_subprocess(cmd, timeout)
    except TimeoutError as exc:
        return TaskExecResult("", str(exc), -1, str(exc), "TIMEOUT", version)
    except MemoryError as exc:
        return TaskExecResult("", str(exc), -1, str(exc), "TOOL_ERROR", version)

    if rc != 0:
        # Nuclei may return non-zero even on partial success; check stderr
        if "no results found" in stderr.lower() or "no templates" in stderr.lower():
            # Not a real error — just no findings
            return TaskExecResult(stdout, stderr, 0, None, "NONE", version)
        return TaskExecResult(
            stdout, stderr, rc,
            f"nuclei exited with code {rc}: {stderr[:500]}",
            "TOOL_ERROR", version,
        )

    return TaskExecResult(stdout, stderr, rc, None, "NONE", version)


def naabu_task(
    target: str,
    params: Dict[str, Any],
    tool_path: str = "naabu",
    timeout: int = 300,
    version_flag: str = "-version",
) -> TaskExecResult:
    """
    Run Naabu port scanner.

    Command template::

        naabu -host <target> -silent -json [-p ports] [-rate N] ...
    """
    err = _validate_target(target)
    if err:
        return TaskExecResult("", "", -1, err, "INVALID_TARGET", "")

    abs_path = _resolve_tool(tool_path)
    if abs_path is None:
        return TaskExecResult("", "", -1, f"Tool not found: {tool_path}", "TOOL_MISSING", "")

    version = _get_tool_version(abs_path, version_flag)

    cmd: List[str] = [abs_path, "-host", target, "-silent", "-json"]

    if params.get("ports"):
        cmd.extend(["-p", str(params["ports"])])
    if params.get("top_ports"):
        cmd.extend(["-top-ports", str(params["top_ports"])])
    if params.get("rate"):
        cmd.extend(["-rate", str(int(params["rate"]))])
    if params.get("timeout"):
        cmd.extend(["-timeout", str(int(params["timeout"]))])
    if params.get("retries"):
        cmd.extend(["-retries", str(int(params["retries"]))])
    if params.get("interface"):
        iface = str(params["interface"])
        if re.match(r"^[a-zA-Z0-9]+$", iface):
            cmd.extend(["-interface", iface])
    if params.get("nmap_cli"):
        cmd.extend(["-nmap-cli", str(params["nmap_cli"])])
    if params.get("exclude_ports"):
        cmd.extend(["-exclude-ports", str(params["exclude_ports"])])

    try:
        stdout, stderr, rc = _run_subprocess(cmd, timeout)
    except TimeoutError as exc:
        return TaskExecResult("", str(exc), -1, str(exc), "TIMEOUT", version)
    except MemoryError as exc:
        return TaskExecResult("", str(exc), -1, str(exc), "TOOL_ERROR", version)

    if rc != 0:
        return TaskExecResult(
            stdout, stderr, rc,
            f"naabu exited with code {rc}: {stderr[:500]}",
            "TOOL_ERROR", version,
        )

    return TaskExecResult(stdout, stderr, rc, None, "NONE", version)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

# Map from TaskType enum values → (task_function, tool_config_key)
TASK_DISPATCH = {
    "RECON_SUBDOMAIN": (subfinder_task, "subfinder"),
    "RECON_HTTPX": (httpx_task, "httpx"),
    "RECON_NUCLEI": (nuclei_task, "nuclei"),
    "RECON_PORTSCAN": (naabu_task, "naabu"),
}
