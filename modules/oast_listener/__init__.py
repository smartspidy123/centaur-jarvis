"""
OAST Listener Module — Out-of-Band Application Security Testing
================================================================
Provides HTTP/DNS callback servers, payload generation, and correlation
for detecting blind vulnerabilities (blind XSS, blind SSRF, blind SQLi, etc.).

Architecture:
    - server.py       → HTTP + optional DNS listener for incoming callbacks
    - correlator.py   → Matches callbacks against registered payloads
    - models.py       → Data structures for callbacks and payloads
    - config.yaml     → All configurable settings

Usage by other modules:
    from modules.oast_listener import generate_payload, get_oast_url
    payload_info = generate_payload(task_id="t1", scan_id="s1", vuln_type="blind_xss")
    # payload_info.url → "http://s1-blind-xss-a3f2c1.oast.example.com:8080"
"""

from modules.oast_listener.models import PayloadInfo, Callback
from modules.oast_listener.correlator import generate_payload, get_oast_url

__all__ = [
    "generate_payload",
    "get_oast_url",
    "PayloadInfo",
    "Callback",
]

__version__ = "1.0.0"
__module_name__ = "oast_listener"
