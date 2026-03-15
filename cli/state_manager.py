"""
State Manager – Saves and loads scan state for resume capability.

Handles:
- Persisting scan progress, completed tasks, findings, activities
- Loading previous state for --resume
- Auto-save at configurable intervals
- Fallback to /tmp if primary directory fails
- Atomic writes to prevent corruption
- State file rotation (keep last N)

Edge Cases Handled:
- Disk full → fallback to /tmp
- Corrupt state file → skip and warn
- Permission denied → fallback directory
- Concurrent access → file locking
"""

import json
import os
import shutil
import time
import threading
import tempfile
import fcntl
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone


class StateManager:
    """Thread-safe scan state persistence manager."""

    def __init__(
        self,
        save_directory: str = ".jarvis_state",
        fallback_directory: str = "/tmp/jarvis_state",
        auto_save_interval: int = 30,
        max_state_files: int = 20,
        logger=None,
    ):
        self.save_directory = Path(save_directory)
        self.fallback_directory = Path(fallback_directory)
        self.auto_save_interval = auto_save_interval
        self.max_state_files = max_state_files
        self.logger = logger
        self._lock = threading.Lock()
        self._auto_save_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._active_directory: Optional[Path] = None

        # Initialize directory
        self._active_directory = self._ensure_directory()

    def _log(self, level: str, msg: str):
        """Safe logging helper."""
        if self.logger:
            getattr(self.logger, level, self.logger.info)(msg)

    def _ensure_directory(self) -> Path:
        """Ensure state directory exists; fallback to /tmp if primary fails."""
        for directory in [self.save_directory, self.fallback_directory]:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                # Test write permission
                test_file = directory / ".write_test"
                test_file.write_text("test")
                test_file.unlink()
                self._log("info", f"[StateManager] Using state directory: {directory}")
                return directory
            except (PermissionError, OSError) as e:
                self._log(
                    "warning",
                    f"[StateManager] Cannot use {directory}: {e}. Trying fallback...",
                )
                continue

        # Last resort: system temp
        tmp = Path(tempfile.mkdtemp(prefix="jarvis_state_"))
        self._log("warning", f"[StateManager] Using temp directory: {tmp}")
        return tmp

    def _state_file_path(self, scan_id: str) -> Path:
        """Get path for a scan's state file."""
        safe_id = scan_id.replace("/", "_").replace("\\", "_")
        return self._active_directory / f"{safe_id}.state.json"

    def save_state(self, scan_id: str, state: Dict[str, Any]) -> bool:
        """
        Atomically save scan state to disk.
        
        Returns True on success, False on failure.
        Uses atomic write (write to temp, then rename) to prevent corruption.
        """
        with self._lock:
            filepath = self._state_file_path(scan_id)
            temp_path = filepath.with_suffix(".tmp")

            state_envelope = {
                "scan_id": scan_id,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "version": "1.0",
                "state": self._serialize_state(state),
            }

            try:
                with open(temp_path, "w") as f:
                    # File locking for concurrent access safety
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except (IOError, OSError):
                        pass  # Best effort locking
                    json.dump(state_envelope, f, indent=2, default=str)
                    f.flush()
                    os.fsync(f.fileno())

                # Atomic rename
                shutil.move(str(temp_path), str(filepath))
                self._log("debug", f"[StateManager] State saved for {scan_id}")
                self._rotate_old_states()
                return True

            except OSError as e:
                self._log("error", f"[StateManager] Failed to save state: {e}")
                # Attempt fallback
                if self._active_directory != self.fallback_directory:
                    self._log(
                        "warning",
                        "[StateManager] Attempting fallback directory for save...",
                    )
                    old_dir = self._active_directory
                    self._active_directory = self._ensure_directory()
                    if self._active_directory != old_dir:
                        return self.save_state(scan_id, state)
                # Clean up temp
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
                return False

    def load_state(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Load saved scan state. Returns None if not found or corrupt.
        Checks both primary and fallback directories.
        """
        with self._lock:
            for directory in [self.save_directory, self.fallback_directory]:
                safe_id = scan_id.replace("/", "_").replace("\\", "_")
                filepath = directory / f"{safe_id}.state.json"

                if not filepath.exists():
                    continue

                try:
                    with open(filepath, "r") as f:
                        envelope = json.load(f)

                    if "state" not in envelope:
                        self._log(
                            "warning",
                            f"[StateManager] Corrupt state file (no 'state' key): {filepath}",
                        )
                        continue

                    self._log(
                        "info",
                        f"[StateManager] Loaded state for {scan_id} "
                        f"(saved at {envelope.get('saved_at', 'unknown')})",
                    )
                    return envelope["state"]

                except json.JSONDecodeError as e:
                    self._log(
                        "error",
                        f"[StateManager] Corrupt state file {filepath}: {e}",
                    )
                    continue
                except OSError as e:
                    self._log(
                        "error",
                        f"[StateManager] Cannot read state file {filepath}: {e}",
                    )
                    continue

            self._log("warning", f"[StateManager] No saved state found for {scan_id}")
            return None

    def list_saved_scans(self) -> List[Dict[str, Any]]:
        """List all saved scan states with metadata."""
        scans = []
        for directory in [self.save_directory, self.fallback_directory]:
            if not directory.exists():
                continue
            for filepath in directory.glob("*.state.json"):
                try:
                    with open(filepath, "r") as f:
                        envelope = json.load(f)
                    scans.append(
                        {
                            "scan_id": envelope.get("scan_id", filepath.stem),
                            "saved_at": envelope.get("saved_at", "unknown"),
                            "file": str(filepath),
                            "size_kb": round(filepath.stat().st_size / 1024, 1),
                        }
                    )
                except (json.JSONDecodeError, OSError):
                    continue
        return scans

    def delete_state(self, scan_id: str) -> bool:
        """Delete saved state for a scan."""
        with self._lock:
            for directory in [self.save_directory, self.fallback_directory]:
                safe_id = scan_id.replace("/", "_").replace("\\", "_")
                filepath = directory / f"{safe_id}.state.json"
                try:
                    if filepath.exists():
                        filepath.unlink()
                        self._log("info", f"[StateManager] Deleted state for {scan_id}")
                        return True
                except OSError as e:
                    self._log(
                        "error",
                        f"[StateManager] Failed to delete state {filepath}: {e}",
                    )
            return False

    def start_auto_save(self, scan_id: str, state_getter):
        """
        Start background thread for periodic auto-save.
        
        Args:
            scan_id: Current scan ID
            state_getter: Callable that returns current state dict
        """
        self._stop_event.clear()

        def _auto_save_loop():
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=self.auto_save_interval)
                if self._stop_event.is_set():
                    break
                try:
                    current_state = state_getter()
                    if current_state:
                        self.save_state(scan_id, current_state)
                except Exception as e:
                    self._log("error", f"[StateManager] Auto-save failed: {e}")

        self._auto_save_thread = threading.Thread(
            target=_auto_save_loop, daemon=True, name="state-auto-save"
        )
        self._auto_save_thread.start()
        self._log("info", f"[StateManager] Auto-save started (every {self.auto_save_interval}s)")

    def stop_auto_save(self):
        """Stop the auto-save background thread."""
        self._stop_event.set()
        if self._auto_save_thread and self._auto_save_thread.is_alive():
            self._auto_save_thread.join(timeout=5)
        self._log("info", "[StateManager] Auto-save stopped")

    def _serialize_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure state is JSON-serializable."""
        serialized = {}
        for key, value in state.items():
            try:
                json.dumps(value, default=str)
                serialized[key] = value
            except (TypeError, ValueError):
                serialized[key] = str(value)
        return serialized

    def _rotate_old_states(self):
        """Remove oldest state files if exceeding max_state_files."""
        if not self._active_directory or not self._active_directory.exists():
            return
        files = sorted(
            self._active_directory.glob("*.state.json"),
            key=lambda f: f.stat().st_mtime,
        )
        while len(files) > self.max_state_files:
            oldest = files.pop(0)
            try:
                oldest.unlink()
                self._log("debug", f"[StateManager] Rotated old state: {oldest.name}")
            except OSError:
                pass
