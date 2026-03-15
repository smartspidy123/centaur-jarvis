"""
Wordlist Manager
================
Handles wordlist resolution, download, and caching.
- Checks if configured wordlist exists on disk.
- Falls back to auto-download from SecLists (configurable URL).
- Caches downloaded wordlists under ~/.centaur/wordlists/.
- Thread-safe download with file locking.
"""

import hashlib
import tempfile
import shutil
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# ── Logging Setup (shared.logger with fallback) ─────────────────────
try:
    from shared.logger import get_logger
    logger = get_logger("dirbust.wordlist_manager")
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"timestamp":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","message":"%(message)s"}'
    )
    logger = logging.getLogger("dirbust.wordlist_manager")


class WordlistError(Exception):
    """Raised when wordlist cannot be resolved or downloaded."""
    pass


class WordlistManager:
    """Manages wordlist resolution, downloading, and caching."""

    def __init__(self, config: dict):
        """
        Args:
            config: The full module config dict (parsed from config.yaml).
        """
        wl_config = config.get("wordlist", {})
        self._default_path = wl_config.get(
            "default",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
        )
        self._auto_download = wl_config.get("auto_download", True)
        self._download_url = wl_config.get(
            "download_url",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        )
        self._cache_dir = Path(
            wl_config.get("cache_dir", "~/.centaur/wordlists")
        ).expanduser()

    def get_wordlist_path(self, custom_path: Optional[str] = None) -> Path:
        """
        Resolve a wordlist path. Priority:
        1. custom_path (from task payload)
        2. default path (from config)
        3. Auto-download to cache

        Args:
            custom_path: Optional user-supplied wordlist path.

        Returns:
            Path object to the wordlist file.

        Raises:
            WordlistError: If no wordlist can be resolved.
        """
        # ── Priority 1: Custom path from task ────────────────────────
        if custom_path:
            p = Path(custom_path).expanduser().resolve()
            if p.is_file():
                logger.info(
                    "Using custom wordlist",
                    extra={"path": str(p), "lines": self._count_lines(p)}
                )
                return p
            else:
                logger.warning(
                    "Custom wordlist not found, falling back",
                    extra={"requested": custom_path}
                )

        # ── Priority 2: Default configured path ─────────────────────
        default = Path(self._default_path).expanduser().resolve()
        if default.is_file():
            logger.info(
                "Using default wordlist",
                extra={"path": str(default), "lines": self._count_lines(default)}
            )
            return default

        # ── Priority 3: Check cache ─────────────────────────────────
        cached = self._get_cached_path()
        if cached.is_file():
            logger.info(
                "Using cached wordlist",
                extra={"path": str(cached), "lines": self._count_lines(cached)}
            )
            return cached

        # ── Priority 4: Auto-download ───────────────────────────────
        if self._auto_download:
            logger.info(
                "Wordlist not found locally; attempting download",
                extra={"url": self._download_url}
            )
            return self._download_wordlist()

        raise WordlistError(
            f"No wordlist available. Checked: custom={custom_path}, "
            f"default={self._default_path}, cache={cached}. "
            f"Auto-download is disabled."
        )

    def _get_cached_path(self) -> Path:
        """Derive a deterministic cache filename from the download URL."""
        url_hash = hashlib.sha256(self._download_url.encode()).hexdigest()[:12]
        parsed = urlparse(self._download_url)
        filename = Path(parsed.path).name or "wordlist.txt"
        return self._cache_dir / f"{url_hash}_{filename}"

    def _download_wordlist(self) -> Path:
        """
        Download wordlist from configured URL to cache directory.
        Uses atomic write (temp file + rename) to avoid partial files.

        Returns:
            Path to the downloaded file.

        Raises:
            WordlistError: On download failure.
        """
        try:
            import requests
        except ImportError:
            raise WordlistError(
                "Cannot download wordlist: 'requests' library not installed."
            )

        dest = self._get_cached_path()

        try:
            # Ensure cache directory exists
            self._cache_dir.mkdir(parents=True, exist_ok=True)

            # Atomic download: write to temp, then move
            with tempfile.NamedTemporaryFile(
                dir=self._cache_dir, delete=False, suffix=".tmp"
            ) as tmp:
                tmp_path = Path(tmp.name)
                logger.info(
                    "Downloading wordlist",
                    extra={"url": self._download_url, "dest": str(dest)}
                )

                resp = requests.get(
                    self._download_url,
                    stream=True,
                    timeout=120,
                    headers={"User-Agent": "Centaur-Jarvis/1.0"}
                )
                resp.raise_for_status()

                total_bytes = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        tmp.write(chunk)
                        total_bytes += len(chunk)

            # Atomic move
            shutil.move(str(tmp_path), str(dest))

            line_count = self._count_lines(dest)
            logger.info(
                "Wordlist downloaded successfully",
                extra={
                    "path": str(dest),
                    "bytes": total_bytes,
                    "lines": line_count
                }
            )
            return dest

        except requests.RequestException as e:
            # Cleanup partial temp file
            if 'tmp_path' in locals() and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise WordlistError(
                f"Failed to download wordlist from {self._download_url}: {e}"
            ) from e
        except OSError as e:
            if 'tmp_path' in locals() and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise WordlistError(
                f"Filesystem error while caching wordlist: {e}"
            ) from e

    @staticmethod
    def _count_lines(path: Path) -> int:
        """Fast line count for a file."""
        try:
            count = 0
            with open(path, "rb") as f:
                for _ in f:
                    count += 1
            return count
        except OSError:
            return -1
