"""
Centaur-Jarvis Advanced HTTP Client Module
==========================================
Provides WAF-evading HTTP capabilities with TLS fingerprint randomization,
proxy rotation, rate limiting, circuit breaking, and HTTP/2 support.

Architecture: Plug-and-play module communicating via Redis queues.
All status strings are UPPERCASE per global architecture rule.
"""

from modules.http_client.client import HttpClient
from modules.http_client.proxy_rotator import ProxyRotator
from modules.http_client.rate_limiter import RateLimiter
from modules.http_client.circuit_breaker import CircuitBreaker
from modules.http_client.tls_fingerprint import TLSFingerprinter
from modules.http_client.user_agents import UserAgentRotator
from modules.http_client.header_forger import HeaderForger

__all__ = [
    "HttpClient",
    "ProxyRotator",
    "RateLimiter",
    "CircuitBreaker",
    "TLSFingerprinter",
    "UserAgentRotator",
    "HeaderForger",
]

__version__ = "1.0.0"
