"""
Smart Fuzzer Module — Centaur-Jarvis VAPT Agent
================================================
Intelligent, AI-driven payload delivery engine with adaptive mutation,
rate-limited execution, and optional AI-powered finding verification.

Public Interface:
    - SmartFuzzer: Main fuzzer class (task consumer + state machine)
    - PayloadGenerator: AI-backed payload creation/mutation
    - FuzzExecutor: Rate-limited HTTP execution engine

Architecture Notes:
    - Consumes tasks from Redis queue `queue:smart_fuzzer`
    - Pushes verified results to `results:incoming`
    - All AI calls routed through modules.ai_routing.router
    - All HTTP calls routed through modules.http_client.client
"""

from modules.smart_fuzzer.fuzzer import SmartFuzzer
from modules.smart_fuzzer.payload_generator import PayloadGenerator
from modules.smart_fuzzer.executor import FuzzExecutor

__all__ = ["SmartFuzzer", "PayloadGenerator", "FuzzExecutor"]
__version__ = "1.0.0"
__module_name__ = "smart_fuzzer"
