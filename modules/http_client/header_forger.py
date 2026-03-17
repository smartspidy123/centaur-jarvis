"""
Header Forger
=============
Generates realistic browser-like HTTP headers to evade WAF header-order
and header-presence fingerprinting.

Key features:
  - Browser-consistent header sets (Sec-Fetch-*, Accept, etc.)
  - Random header order to defeat signature-based detection
  - Correlation between User-Agent browser family and headers

All status strings are UPPERCASE.
"""

import random
from collections import OrderedDict
from typing import Dict, Optional

try:
    from shared.logger import get_logger
    logger = get_logger("http_client.header_forger")
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

    logger = logging.getLogger("http_client.header_forger")
    if not logger.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(_JsonFormatter())
        logger.addHandler(_h)
        logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Header templates per browser family
# ---------------------------------------------------------------------------

_COMMON_ACCEPT_HTML = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)
_FIREFOX_ACCEPT_HTML = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,*/*;q=0.8"
)

_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.8",
    "en-US,en;q=0.9,de;q=0.7",
]

_SEC_CH_UA_CHROME = [
    '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    '"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="99"',
    '"Chromium";v="122", "Google Chrome";v="122", "Not-A.Brand";v="99"',
]

_SEC_CH_UA_EDGE = [
    '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
    '"Chromium";v="123", "Microsoft Edge";v="123", "Not-A.Brand";v="99"',
]


class HeaderForger:
    """Generate browser-like HTTP request headers with randomised order."""

    def __init__(self) -> None:
        logger.debug("HeaderForger initialised")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def forge(
        self,
        url: str,
        user_agent: str,
        browser_family: str = "chrome",
        extra_headers: Optional[Dict[str, str]] = None,
        *,
        randomise_order: bool = True,
    ) -> Dict[str, str]:
        """Build a full header dict mimicking a real browser.

        Args:
            url: Target URL (used for Host / Referer).
            user_agent: The User-Agent to include.
            browser_family: 'chrome', 'firefox', 'edge', 'safari'.
            extra_headers: Additional headers to merge (override generated ones).
            randomise_order: Shuffle header key order.

        Returns:
            Ordered dict of headers.
        """
        family = browser_family.lower()
        builder = {
            "chrome": self._chrome_headers,
            "edge": self._edge_headers,
            "firefox": self._firefox_headers,
            "safari": self._safari_headers,
        }
        fn = builder.get(family, self._chrome_headers)
        headers = fn(user_agent)

        # Common additions
        headers["Accept-Language"] = random.choice(_ACCEPT_LANGUAGES)
        headers["Accept-Encoding"] = "gzip, deflate, br"

        if extra_headers:
            headers.update(extra_headers)

        if randomise_order:
            items = list(headers.items())
            random.shuffle(items)
            headers = OrderedDict(items)

        return dict(headers)

    # ------------------------------------------------------------------
    # Browser-specific header builders
    # ------------------------------------------------------------------

    def _chrome_headers(self, ua: str) -> Dict[str, str]:
        return {
            "User-Agent": ua,
            "Accept": _COMMON_ACCEPT_HTML,
            "Sec-Ch-Ua": random.choice(_SEC_CH_UA_CHROME),
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"']),
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
        }

    def _edge_headers(self, ua: str) -> Dict[str, str]:
        h = self._chrome_headers(ua)
        h["Sec-Ch-Ua"] = random.choice(_SEC_CH_UA_EDGE)
        return h

    def _firefox_headers(self, ua: str) -> Dict[str, str]:
        return {
            "User-Agent": ua,
            "Accept": _FIREFOX_ACCEPT_HTML,
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive",
            "DNT": "1",
        }

    def _safari_headers(self, ua: str) -> Dict[str, str]:
        return {
            "User-Agent": ua,
            "Accept": _COMMON_ACCEPT_HTML,
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive",
        }
