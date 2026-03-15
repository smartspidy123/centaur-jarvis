"""
Entrypoint for running the reporting module as:
    python -m modules.reporting --scan-id SCAN_ID
"""

from modules.reporting.generator import main

if __name__ == "__main__":
    main()
