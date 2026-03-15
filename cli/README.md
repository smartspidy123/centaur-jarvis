# Centaur-Jarvis CLI Module

## Overview

The CLI module is the **master controller** for Centaur-Jarvis, providing a unified command-line
interface with an advanced real-time hacker-style dashboard. It orchestrates the full VAPT
scan lifecycle across all backend modules.

## Architecture
┌─────────────────────────────────────────────────────────────────┐
│ CLI (main.py) │
│ │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│ │ argparse │ │ config │ │ signal │ │
│ │ (args) │ │ (yaml) │ │ (Ctrl+C) │ │
│ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ │
│ │ │ │ │
│ ▼ ▼ ▼ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Scan Controller │ │
│ │ ┌─────────┐ ┌─────────┐ ┌─────────┐ │ │
│ │ │ Target │ │ Phase │ │ Result │ │ │
│ │ │ Parser │ │ Runner │ │ Listener│ │ │
│ │ └────┬────┘ └────┬────┘ └────┬────┘ │ │
│ │ │ │ │ │ │
│ │ ▼ ▼ ▼ │ │
│ │ ┌───────────────────────────────────────┐ │ │
│ │ │ Thread-Safe Tracking Collections │ │ │
│ │ │ ┌──────────┐ ┌───────┐ ┌──────────┐ │ │ │
│ │ │ │Activities│ │Events │ │ Errors │ │ │ │
│ │ │ └──────────┘ └───────┘ └──────────┘ │ │ │
│ │ └───────────────────────────────────────┘ │ │
│ └─────────────────────────┬───────────────────────────┘ │
│ │ │
│ ┌──────────────────┼──────────────────┐ │
│ ▼ ▼ ▼ │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ Live │ │ Process │ │ State │ │
│ │ Display │ │ Manager │ │ Manager │ │
│ │ (rich) │ │ (popen) │ │ (json) │ │
│ └────┬─────┘ └────┬─────┘ └────┬─────┘ │
│ │ │ │ │
│ ▼ ▼ ▼ │
│ ┌─────────┐ ┌───────────┐ ┌──────────┐ │
│ │Terminal │ │Subprocess │ │ Disk │ │
│ │ Output │ │ Workers │ │ State │ │
│ └─────────┘ └─────┬─────┘ └──────────┘ │
│ │ │
└──────────────────────────┼───────────────────────────────────────┘
│
┌──────▼──────┐
│ Redis │
│ Queues │
└─────────────┘

text


## Quick Start

```bash
# Install dependencies
pip install rich pyyaml redis psutil tenacity

# Basic scan
python -m cli.main --target https://example.com

# Full scan with verbose output
python -m cli.main --target https://example.com --profile full --verbose

# Scan multiple targets from file
python -m cli.main --target targets.txt --profile full

# Resume paused scan
python -m cli.main --resume SCAN_12345678

# Manual mode (services already running)
python -m cli.main --target https://example.com --manual

# List profiles
python -m cli.main --list-profiles

# List saved scans
python -m cli.main --list-scans
Scan Profiles
Profile	Phases	Tools	Fuzzing	Sniper
quick	recon	nuclei	✘	✘
full	recon→fuzzing→sniper	subfinder, httpx, nuclei, etc.	✔	✔
recon_only	recon	All recon tools	✘	✘
custom	configurable	configurable	✘	✘
Dashboard Panels
Banner – ASCII art header
Scan Info – ID, target, profile, phase, elapsed time, status
Current Activity – Running tasks with elapsed time
Live Events – Color-coded scrolling event feed
Stats – Task counts, findings, AI/RAG usage
Tool Summaries – Ports, subdomains, endpoints, technologies
Errors – Failures with timestamps
Queue Status – Redis queue lengths
Edge Cases
See main task specification for full edge case table. Key mitigations:

Redis down: Red error + suggest --manual mode
Service crash: Auto-restart up to N times, error in dashboard
Ctrl+C: Save state + print resume command
Disk full: Fallback to /tmp for state saves
Duplicate CLI: PID file detection + error message
Target unreachable: Error in events, continue with other targets
