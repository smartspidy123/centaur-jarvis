"""
Process Manager – Starts, monitors, and stops background services.

Handles:
- Starting orchestrator, recon workers, fuzzer, sniper as subprocesses
- Health monitoring with auto-restart on crash
- Graceful shutdown with SIGTERM → wait → SIGKILL
- PID file management to prevent duplicate instances
- Manual mode support (skip process management)

Edge Cases Handled:
- Service binary not found → clear error
- Permission denied → suggest --manual
- Zombie processes → force kill
- PID file stale → detect and clean
- Child processes hanging on shutdown → escalate to SIGKILL
"""

import os
import sys
import signal
import time
import subprocess
import threading
from pathlib import Path
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ProcessInfo:
    """Metadata for a managed subprocess."""
    name: str
    module: str
    process: Optional[subprocess.Popen] = None
    pid: Optional[int] = None
    required: bool = True
    restart_on_crash: bool = True
    max_restarts: int = 3
    restart_count: int = 0
    started_at: Optional[str] = None
    status: str = "STOPPED"  # STOPPED, RUNNING, CRASHED, RESTARTING


class ProcessManager:
    """
    Manages background service processes for Centaur-Jarvis.
    
    In non-manual mode, starts all configured services as subprocesses.
    In manual mode, assumes services are already running externally.
    """

    PID_DIR = Path(".jarvis_pids")

    def __init__(self, config: Dict[str, Any], manual_mode: bool = False, logger=None):
        self.config = config
        self.manual_mode = manual_mode
        self.logger = logger
        self._processes: Dict[str, ProcessInfo] = {}
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._errors: List[Dict[str, Any]] = []

        if not manual_mode:
            self._init_pid_directory()

    def _log(self, level: str, msg: str):
        if self.logger:
            getattr(self.logger, level, self.logger.info)(msg)

    def _init_pid_directory(self):
        """Create PID directory, handle permission issues."""
        try:
            self.PID_DIR.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            self._log("error", f"[ProcessManager] Cannot create PID directory: {self.PID_DIR}")
            self._errors.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": f"Permission denied creating {self.PID_DIR}",
                "suggestion": "Run with --manual mode or fix permissions",
            })

    def check_duplicate_instance(self) -> bool:
        """
        Check if another CLI instance is already running.
        Returns True if duplicate detected.
        """
        pid_file = self.PID_DIR / "cli_master.pid"
        if pid_file.exists():
            try:
                old_pid = int(pid_file.read_text().strip())
                # Check if process is actually alive
                try:
                    os.kill(old_pid, 0)
                    # Process exists
                    self._log(
                        "error",
                        f"[ProcessManager] Another instance running (PID {old_pid}). "
                        f"Kill it first or delete {pid_file}",
                    )
                    return True
                except OSError:
                    # Stale PID file – process is dead
                    self._log(
                        "info",
                        f"[ProcessManager] Stale PID file found (PID {old_pid}). Cleaning up.",
                    )
                    pid_file.unlink(missing_ok=True)
                    return False
            except (ValueError, OSError):
                pid_file.unlink(missing_ok=True)
                return False

        # Write our PID
        try:
            pid_file.write_text(str(os.getpid()))
        except OSError:
            pass
        return False

    def start_services(self, required_phases: List[str]) -> Dict[str, str]:
        """
        Start background services needed for the scan phases.
        
        Args:
            required_phases: List of phases like ["recon", "fuzzing", "sniper"]
            
        Returns:
            Dict mapping service name → status
        """
        if self.manual_mode:
            self._log("info", "[ProcessManager] Manual mode – skipping service startup")
            return {"mode": "manual", "status": "SKIPPED"}

        process_configs = self.config.get("processes", {})
        results = {}

        # Always start orchestrator
        if "orchestrator" in process_configs:
            results["orchestrator"] = self._start_process(
                "orchestrator", process_configs["orchestrator"]
            )

        # Start phase-specific workers
        phase_worker_map = {
            "recon": "recon_worker",
            "fuzzing": "fuzzer_worker",
            "sniper": "sniper_worker",
        }

        for phase in required_phases:
            worker_name = phase_worker_map.get(phase)
            if worker_name and worker_name in process_configs:
                results[worker_name] = self._start_process(
                    worker_name, process_configs[worker_name]
                )

        # Start monitor thread
        self._start_monitor()
        return results

    def _start_process(self, name: str, proc_config: Dict[str, Any]) -> str:
        """Start a single background process."""
        module = proc_config.get("module", "")
        required = proc_config.get("required", False)
        restart_on_crash = proc_config.get("restart_on_crash", True)
        max_restarts = proc_config.get("max_restarts", 3)

        info = ProcessInfo(
            name=name,
            module=module,
            required=required,
            restart_on_crash=restart_on_crash,
            max_restarts=max_restarts,
        )

        try:
            cmd = [sys.executable, "-m", module]
            self._log("info", f"[ProcessManager] Starting {name}: {' '.join(cmd)}")

            with open(log_file, "a") as lf:
                proc = subprocess.Popen(
                    cmd_parts,
                    stdout=lf,                # ✅ Output log file mein jayega
                    stderr=lf,                # ✅ Errors bhi log file mein
                    start_new_session=True,
                    cwd=self.project_root
                )


            info.process = proc
            info.pid = proc.pid
            info.status = "RUNNING"
            info.started_at = datetime.now(timezone.utc).isoformat()

            # Write PID file
            try:
                (self.PID_DIR / f"{name}.pid").write_text(str(proc.pid))
            except OSError:
                pass

            with self._lock:
                self._processes[name] = info

            self._log("info", f"[ProcessManager] {name} started (PID {proc.pid})")
            return "RUNNING"

        except FileNotFoundError:
            error_msg = f"Module '{module}' not found. Is it installed?"
            self._log("error", f"[ProcessManager] {error_msg}")
            info.status = "CRASHED"
            self._errors.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "service": name,
                "error": error_msg,
            })
            with self._lock:
                self._processes[name] = info
            return "FAILED" if required else "SKIPPED"

        except PermissionError:
            error_msg = f"Permission denied starting {name}. Use --manual mode."
            self._log("error", f"[ProcessManager] {error_msg}")
            info.status = "CRASHED"
            self._errors.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "service": name,
                "error": error_msg,
            })
            with self._lock:
                self._processes[name] = info
            return "FAILED"

        except Exception as e:
            error_msg = f"Unexpected error starting {name}: {e}"
            self._log("error", f"[ProcessManager] {error_msg}")
            info.status = "CRASHED"
            self._errors.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "service": name,
                "error": error_msg,
            })
            with self._lock:
                self._processes[name] = info
            return "FAILED"

    def _start_monitor(self):
        """Start background thread to monitor process health."""
        self._stop_event.clear()

        def _monitor_loop():
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=5)
                if self._stop_event.is_set():
                    break
                self._check_processes()

        self._monitor_thread = threading.Thread(
            target=_monitor_loop, daemon=True, name="process-monitor"
        )
        self._monitor_thread.start()

    def _check_processes(self):
        """Check if managed processes are still alive; restart if needed."""
        with self._lock:
            for name, info in self._processes.items():
                if info.status != "RUNNING" or info.process is None:
                    continue

                retcode = info.process.poll()
                if retcode is not None:
                    # Process exited
                    info.status = "CRASHED"
                    self._log(
                        "error",
                        f"[ProcessManager] {name} crashed (exit code {retcode})",
                    )
                    self._errors.append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "service": name,
                        "error": f"Crashed with exit code {retcode}",
                    })

                    if info.restart_on_crash and info.restart_count < info.max_restarts:
                        info.restart_count += 1
                        info.status = "RESTARTING"
                        self._log(
                            "warning",
                            f"[ProcessManager] Restarting {name} "
                            f"(attempt {info.restart_count}/{info.max_restarts})",
                        )
                        # Release lock for restart
                        # We'll handle restart outside the loop to avoid holding lock
                        threading.Thread(
                            target=self._restart_process,
                            args=(name,),
                            daemon=True,
                        ).start()

    def _restart_process(self, name: str):
        """Restart a crashed process."""
        time.sleep(2)  # Brief delay before restart
        with self._lock:
            info = self._processes.get(name)
            if not info:
                return

        proc_config = self.config.get("processes", {}).get(name, {})
        result = self._start_process(name, proc_config)
        if result == "RUNNING":
            self._log("info", f"[ProcessManager] {name} restarted successfully")

    def stop_all(self, timeout: int = 10):
        """
        Gracefully stop all managed processes.
        SIGTERM → wait(timeout) → SIGKILL for stragglers.
        """
        self._stop_event.set()

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3)

        with self._lock:
            processes_to_stop = list(self._processes.values())

        if not processes_to_stop:
            return

        self._log("info", "[ProcessManager] Stopping all services...")

        # Phase 1: SIGTERM
        for info in processes_to_stop:
            if info.process and info.process.poll() is None:
                try:
                    self._log("info", f"[ProcessManager] Sending SIGTERM to {info.name} (PID {info.pid})")
                    os.killpg(os.getpgid(info.pid), signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        info.process.terminate()
                    except Exception:
                        pass

        # Phase 2: Wait
        deadline = time.time() + timeout
        for info in processes_to_stop:
            if info.process and info.process.poll() is None:
                remaining = max(0.1, deadline - time.time())
                try:
                    info.process.wait(timeout=remaining)
                    self._log("info", f"[ProcessManager] {info.name} stopped gracefully")
                except subprocess.TimeoutExpired:
                    pass

        # Phase 3: SIGKILL for stragglers
        for info in processes_to_stop:
            if info.process and info.process.poll() is None:
                try:
                    self._log(
                        "warning",
                        f"[ProcessManager] Force-killing {info.name} (PID {info.pid})",
                    )
                    os.killpg(os.getpgid(info.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        info.process.kill()
                    except Exception:
                        pass

                self._errors.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "service": info.name,
                    "error": "Required SIGKILL to stop",
                })

            info.status = "STOPPED"

        # Clean PID files
        self._clean_pid_files()
        self._log("info", "[ProcessManager] All services stopped")

    def _clean_pid_files(self):
        """Remove PID files on shutdown."""
        if self.PID_DIR.exists():
            for pid_file in self.PID_DIR.glob("*.pid"):
                try:
                    pid_file.unlink()
                except OSError:
                    pass

    def get_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all managed processes."""
        with self._lock:
            status = {}
            for name, info in self._processes.items():
                alive = False
                if info.process:
                    alive = info.process.poll() is None
                status[name] = {
                    "status": info.status if alive else ("STOPPED" if info.status == "STOPPED" else "CRASHED"),
                    "pid": info.pid,
                    "restarts": info.restart_count,
                    "started_at": info.started_at,
                }
            return status

    def health_check(self, controller):
        """Check all managed processes and report dead ones to controller."""
        import time
        for name, info in list(self._processes.items()):
            proc = info.process
            if proc and proc.poll() is not None:  # process has exited
                controller._add_error(f"Worker '{name}' crashed (exit code: {proc.returncode})")
                # Optionally attempt restart
                proc_config = self.config.get("processes", {}).get(name, {})
                self._start_process(name, proc_config)
                time.sleep(1)  # Brief pause after restart

    def get_errors(self) -> List[Dict[str, Any]]:
        """Return accumulated process errors."""
        return list(self._errors)
