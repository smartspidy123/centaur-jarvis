"""
Playwright Renderer Module — Centaur‑Jarvis VAPT Agent
======================================================
Renders SPAs via headless Chromium, intercepts XHR/Fetch calls,
extracts endpoints, parameters, authentication tokens, and form
structures.  Communicates exclusively through Redis queues.

Queue consumed : queue:playwright
Results pushed : results:incoming
Status updated : task:{id}  (Redis hash, field "status")
"""

__version__ = "1.0.0"
__module_name__ = "playwright_rend"
