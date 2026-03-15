"""
IDOR Analyzer Module — Centaur‑Jarvis VAPT Agent
=================================================
Detects Insecure Direct Object Reference (IDOR) and Broken Object Level
Authorization (BOLA) vulnerabilities by comparing HTTP responses from two
distinct user sessions against the same API endpoints.

Architecture contract:
    • Consumes tasks from  Redis queue ``queue:idor``
    • Publishes results to Redis queue ``results:incoming``
    • Status updates written to ``task:status:<task_id>`` hashes
    • All status strings UPPERCASE (COMPLETED, FAILED, PROCESSING, TIMEOUT)
    • Result dicts always carry a mandatory ``data`` field
    • JSON‑structured logging via ``shared.logger`` (graceful fallback)
    • Graceful SIGTERM handling — finish current endpoint then exit
    • Memory‑buffered result queue (≤100) when Redis is unreachable
"""

__version__ = "1.0.0"
__module_name__ = "idor_analyzer"
