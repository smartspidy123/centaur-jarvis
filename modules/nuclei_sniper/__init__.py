"""
Nuclei Sniper Module
====================
AI-powered CVE monitoring, template generation, validation, and execution.

This module continuously monitors for new CVEs via RSS feeds, uses AI to
generate self-healing Nuclei templates, validates them, and pushes them
to the recon worker for execution.

Architecture Rule Compliance:
- 360-degree edge-case handling
- No silent failures
- Plug-and-play modularity
- Comprehensive telemetry
- All status strings UPPERCASE
- Result dicts include mandatory `data` field
"""

from modules.nuclei_sniper.monitor import CVEMonitor
from modules.nuclei_sniper.generator import TemplateGenerator
from modules.nuclei_sniper.validator import TemplateValidator
from modules.nuclei_sniper.executor import TemplateExecutor

__all__ = [
    "CVEMonitor",
    "TemplateGenerator",
    "TemplateValidator",
    "TemplateExecutor",
]

__version__ = "1.0.0"
__module_name__ = "nuclei_sniper"
