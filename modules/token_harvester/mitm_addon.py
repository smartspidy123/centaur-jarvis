#!/usr/bin/env python3
"""
mitm_addon.py — Mitmproxy Entry Point for Token Harvester
==========================================================

Usage:
  mitmdump -s modules/token_harvester/mitm_addon.py
  mitmproxy -s modules/token_harvester/mitm_addon.py

Or standalone mode:
  python modules/token_harvester/mitm_addon.py [--port 8080] [--config path/to/config.yaml]

This file bootstraps the TokenHarvester addon for mitmproxy.
"""

import atexit
import os
import signal
import sys

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so `modules.*` and `shared.*` resolve.
# When mitmproxy loads this file with `-s`, __file__ is the addon file.
# We walk up to the project root (parent of `modules/`).
# ---------------------------------------------------------------------------
_this_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.abspath(os.path.join(_this_dir, "..", ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from modules.token_harvester.harvester import TokenHarvester

# ---------------------------------------------------------------------------
# Try to import shared logger; fall back to stdlib
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger
    logger = get_logger("mitm_addon")
except (ImportError, ModuleNotFoundError):
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    logger = logging.getLogger("mitm_addon")

# ---------------------------------------------------------------------------
# Configuration path — can be overridden via environment variable
# ---------------------------------------------------------------------------
_config_path = os.environ.get("JARVIS_HARVESTER_CONFIG", None)

# ---------------------------------------------------------------------------
# Global addon instance
# ---------------------------------------------------------------------------
_harvester: TokenHarvester = None  # type: ignore


def _initialize():
    """Initialize the harvester addon. Called once when mitmproxy loads this script."""
    global _harvester
    try:
        logger.info("=" * 60)
        logger.info("  Token Harvester Addon — Loading")
        logger.info("=" * 60)
        _harvester = TokenHarvester(config_path=_config_path)

        # Register shutdown hook
        atexit.register(_shutdown)

        logger.info("Token Harvester addon loaded and ready.")
    except Exception as exc:
        logger.critical("FATAL: Failed to initialize Token Harvester: %s", exc, exc_info=True)
        # We do NOT call sys.exit here because mitmproxy manages the process.
        # Instead, we set _harvester to None and the hooks will be no-ops.
        _harvester = None


def _shutdown():
    """Graceful shutdown handler."""
    global _harvester
    if _harvester is not None:
        _harvester.shutdown()
        _harvester = None


# ---------------------------------------------------------------------------
# Mitmproxy addon class wrapper
# ---------------------------------------------------------------------------

class TokenHarvesterAddon:
    """
    Thin wrapper that mitmproxy recognizes as an addon.
    Delegates to the TokenHarvester instance.
    """

    def __init__(self):
        _initialize()

    def request(self, flow):
        """mitmproxy request hook."""
        if _harvester is None:
            return
        try:
            _harvester.request(flow)
        except Exception as exc:
            logger.error("Unhandled error in request hook: %s", exc, exc_info=True)

    def response(self, flow):
        """mitmproxy response hook."""
        if _harvester is None:
            return
        try:
            _harvester.response(flow)
        except Exception as exc:
            logger.error("Unhandled error in response hook: %s", exc, exc_info=True)

    def done(self):
        """mitmproxy shutdown hook."""
        _shutdown()


# ---------------------------------------------------------------------------
# Mitmproxy addon registration — THIS IS WHAT MITMPROXY LOADS
# ---------------------------------------------------------------------------
addons = [TokenHarvesterAddon()]


# ---------------------------------------------------------------------------
# Standalone Mode
# ---------------------------------------------------------------------------

def _run_standalone():
    """
    Run mitmproxy programmatically (standalone testing mode).
    Usage: python mitm_addon.py [--port PORT] [--config CONFIG_PATH]
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Centaur-Jarvis Token Harvester — Standalone Mode",
    )
    parser.add_argument("--port", type=int, default=8080, help="Proxy port (default: 8080)")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml")
    parser.add_argument("--mode", choices=["regular", "transparent", "upstream"],
                        default="regular", help="Proxy mode")
    parser.add_argument("--ssl-insecure", action="store_true",
                        help="Do not verify upstream SSL certificates")
    args = parser.parse_args()

    global _config_path
    if args.config:
        _config_path = args.config

    logger.info("Starting mitmproxy in standalone mode on port %d…", args.port)
    logger.info("Configure your browser proxy to: http://127.0.0.1:%d", args.port)
    logger.info("Install mitmproxy CA cert: http://mitm.it (through the proxy)")

    try:
        from mitmproxy.tools.main import mitmdump

        sys.argv = [
            "mitmdump",
            "--listen-port", str(args.port),
            "-s", os.path.abspath(__file__),
        ]
        if args.ssl_insecure:
            sys.argv.append("--ssl-insecure")

        mitmdump()

    except ImportError:
        logger.critical(
            "mitmproxy not installed. Install it: pip install mitmproxy"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Shutting down…")
        _shutdown()
    except Exception as exc:
        logger.critical("Failed to start mitmproxy: %s", exc, exc_info=True)
        _shutdown()
        sys.exit(1)


if __name__ == "__main__":
    _run_standalone()