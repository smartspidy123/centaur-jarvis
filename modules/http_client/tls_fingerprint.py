"""
TLS Fingerprint Manager
========================
Randomises JA3/JA4 TLS fingerprints using curl_cffi browser impersonation.

If curl_cffi is not installed, this module transparently degrades to a no-op
that logs a WARNING. The client module handles the fallback to plain requests.

All status strings are UPPERCASE.
"""

import random
from typing import List, Optional, Tuple

try:
    from shared.logger import get_logger
    logger = get_logger("http_client.tls_fingerprint")
except ImportError:
    import logging
    import json as _json

    class _JsonFormatter(logging.Formatter):
        def format(self, record):
            return _json.dumps({
                "timestamp": self.formatTime(record),
                "level": record.levelname,
                "module": record.name,
                "message": record.getMessage(),
            })

    logger = logging.getLogger("http_client.tls_fingerprint")
    if not logger.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(_JsonFormatter())
        logger.addHandler(_h)
        logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# curl_cffi availability check
# ---------------------------------------------------------------------------
CURL_CFFI_AVAILABLE: bool = False
try:
    from curl_cffi import requests as curl_requests  # noqa: F401
    CURL_CFFI_AVAILABLE = True
    logger.info("curl_cffi is available — TLS impersonation ENABLED")
except ImportError:
    logger.warning(
        "curl_cffi not installed — TLS fingerprint impersonation DISABLED. "
        "Install with: pip install curl_cffi"
    )

# ---------------------------------------------------------------------------
# Default impersonation profiles (curl_cffi browser strings)
# ---------------------------------------------------------------------------
DEFAULT_PROFILES: List[str] = [
    "chrome110",
    "chrome107",
    "chrome104",
    "chrome101",
    "chrome100",
    "chrome99",
    "safari15_5",
    "safari15_3",
    "edge101",
    "edge99",
]


class TLSFingerprinter:
    """Manages TLS fingerprint rotation via curl_cffi impersonation profiles.

    Thread-safe: only immutable config + random selection.
    """

    def __init__(
        self,
        profiles: Optional[List[str]] = None,
        rotate_per_request: bool = True,
    ) -> None:
        self._profiles: List[str] = list(profiles) if profiles else list(DEFAULT_PROFILES)
        self._rotate_per_request = rotate_per_request
        self._current: str = random.choice(self._profiles) if self._profiles else "chrome110"
        self._available = CURL_CFFI_AVAILABLE

        if not self._profiles:
            logger.warning("Empty TLS profiles list; using default 'chrome110'")
            self._profiles = ["chrome110"]

        logger.debug(
            "TLSFingerprinter initialised",
            extra={
                "profiles": len(self._profiles),
                "rotate_per_request": rotate_per_request,
                "curl_cffi_available": self._available,
            },
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        """Whether curl_cffi impersonation is usable."""
        return self._available

    def get_profile(self) -> str:
        """Return the current (or rotated) impersonation profile string."""
        if self._rotate_per_request:
            self._current = random.choice(self._profiles)
        logger.debug("TLS profile selected: %s", self._current)
        return self._current

    def get_browser_family(self, profile: Optional[str] = None) -> str:
        """Map a profile string to a browser family name."""
        p = (profile or self._current).lower()
        if p.startswith("chrome"):
            return "chrome"
        if p.startswith("safari"):
            return "safari"
        if p.startswith("edge"):
            return "edge"
        if p.startswith("firefox"):
            return "firefox"
        return "chrome"  # safe default

    def get_profile_and_family(self) -> Tuple[str, str]:
        """Convenience: return (profile, browser_family)."""
        profile = self.get_profile()
        family = self.get_browser_family(profile)
        return profile, family
