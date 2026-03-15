"""
Token Harvester Module — Centaur-Jarvis VAPT Agent
===================================================

Passively intercepts HTTP/HTTPS traffic via mitmproxy, extracts authentication
tokens (JWTs, cookies, CSRF tokens, Authorization headers), and stores them
in Redis for consumption by downstream modules (recon, fuzzer, etc.).

Architecture Principles:
  - 360-degree edge-case handling
  - No silent failures
  - Plug-and-play modularity
  - Comprehensive telemetry

Usage:
  mitmdump -s modules/token_harvester/mitm_addon.py

Or programmatically:
  from modules.token_harvester import get_tokens_for_domain
  tokens = get_tokens_for_domain("example.com")
"""

__version__ = "1.0.0"
__module_name__ = "token_harvester"

from modules.token_harvester.harvester import (
    TokenHarvester,
    get_tokens_for_domain,
    get_all_harvested_domains,
    cleanup_expired_tokens,
    get_token_stats,
)

__all__ = [
    "TokenHarvester",
    "get_tokens_for_domain",
    "get_all_harvested_domains",
    "cleanup_expired_tokens",
    "get_token_stats",
]