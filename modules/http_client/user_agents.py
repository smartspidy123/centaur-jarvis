"""
User-Agent Rotator
==================
Provides realistic, rotating browser User-Agent strings.
Updated periodically to match current browser versions.

All status strings are UPPERCASE per global architecture rule.
"""

import random
import time
from typing import Optional, List

# ---------------------------------------------------------------------------
# Attempt shared.logger; fallback to stdlib
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger
    logger = get_logger("http_client.user_agents")
except ImportError:
    import logging
    import json as _json

    class _JsonFormatter(logging.Formatter):
        def format(self, record):
            log_obj = {
                "timestamp": self.formatTime(record),
                "level": record.levelname,
                "module": record.name,
                "message": record.getMessage(),
            }
            if record.exc_info and record.exc_info[0]:
                log_obj["exception"] = self.formatException(record.exc_info)
            return _json.dumps(log_obj)

    logger = logging.getLogger("http_client.user_agents")
    if not logger.handlers:
        _handler = logging.StreamHandler()
        _handler.setFormatter(_JsonFormatter())
        logger.addHandler(_handler)
        logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Realistic User-Agent pools (Chrome, Firefox, Edge, Safari) — late 2024/2025
# ---------------------------------------------------------------------------
_CHROME_UAS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

_FIREFOX_UAS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

_EDGE_UAS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

_SAFARI_UAS: List[str] = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# Combine all pools
_ALL_UAS: List[str] = _CHROME_UAS + _FIREFOX_UAS + _EDGE_UAS + _SAFARI_UAS


class UserAgentRotator:
    """Rotates realistic browser User-Agent strings.

    Supports per-request rotation or sticky sessions.
    Thread-safe (uses only immutable reads + random).
    """

    def __init__(
        self,
        rotate_per_request: bool = True,
        custom_agents: Optional[List[str]] = None,
    ) -> None:
        self._rotate_per_request = rotate_per_request
        self._agents: List[str] = list(custom_agents) if custom_agents else list(_ALL_UAS)
        if not self._agents:
            logger.warning("No user-agents provided; using hardcoded default")
            self._agents = list(_ALL_UAS)
        self._current: str = random.choice(self._agents)
        self._last_rotated: float = time.monotonic()
        logger.debug(
            "UserAgentRotator initialised",
            extra={"pool_size": len(self._agents), "rotate_per_request": rotate_per_request},
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self) -> str:
        """Return a User-Agent string, rotating if configured."""
        if self._rotate_per_request:
            self._current = random.choice(self._agents)
            self._last_rotated = time.monotonic()
        return self._current

    def get_for_browser(self, browser: str) -> str:
        """Return a UA matching a specific browser family.

        Args:
            browser: One of 'chrome', 'firefox', 'edge', 'safari'.
        """
        mapping = {
            "chrome": _CHROME_UAS,
            "firefox": _FIREFOX_UAS,
            "edge": _EDGE_UAS,
            "safari": _SAFARI_UAS,
        }
        pool = mapping.get(browser.lower())
        if not pool:
            logger.warning("Unknown browser '%s'; returning random UA", browser)
            return self.get()
        return random.choice(pool)

    def detect_browser_family(self, ua: Optional[str] = None) -> str:
        """Return the browser family of a UA string (or current)."""
        ua = ua or self._current
        ua_lower = ua.lower()
        if "edg/" in ua_lower:
            return "edge"
        if "chrome" in ua_lower:
            return "chrome"
        if "firefox" in ua_lower:
            return "firefox"
        if "safari" in ua_lower:
            return "safari"
        return "unknown"

    @property
    def pool_size(self) -> int:
        return len(self._agents)
