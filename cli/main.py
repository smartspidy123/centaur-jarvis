#!/usr/bin/env python3
"""
Centaur-Jarvis CLI – Master Entry Point

Usage:
    python -m cli.main --target https://example.com
    python -m cli.main --target https://example.com --profile full
    python -m cli.main --target targets.txt
    python -m cli.main --resume SCAN_12345678
    python -m cli.main --target https://example.com --manual
    python -m cli.main --target https://example.com --verbose
    python -m cli.main --list-profiles
    python -m cli.main --list-scans

Edge Cases Handled:
- No arguments → help message
- Invalid profile → fallback to default + warning
- No target and no resume → error
- Ctrl+C → graceful shutdown + state save
- Duplicate instance → error + exit
- Missing dependencies → clear error messages
"""

import sys
import os
import signal
import threading
import time
import argparse
from pathlib import Path
from typing import Optional, Dict, Any

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ── Dependency Check ──────────────────────────────────────────────────

def check_dependencies():
    """Verify required packages are installed."""
    missing = []
    try:
        import yaml
    except ImportError:
        missing.append("pyyaml")
    try:
        import redis
    except ImportError:
        missing.append("redis")
    try:
        import rich
    except ImportError:
        missing.append("rich")

    if missing:
        print(f"\n[ERROR] Missing required packages: {', '.join(missing)}")
        print(f"Install with: pip install {' '.join(missing)}\n")
        sys.exit(1)


check_dependencies()

import yaml
from rich.console import Console

from cli.scan_controller import ScanController
from cli.live_display import LiveDisplay, BANNER_ART, HAS_RICH
from cli.process_manager import ProcessManager
from cli.state_manager import StateManager


# ── Global State ──────────────────────────────────────────────────────

console = Console()
shutdown_event = threading.Event()
scan_controller: Optional[ScanController] = None
process_manager: Optional[ProcessManager] = None
state_manager: Optional[StateManager] = None


# ── Config Loading ────────────────────────────────────────────────────

def load_config() -> Dict[str, Any]:
    """Load CLI configuration from config.yaml."""
    config_path = Path(__file__).parent / "config.yaml"

    if not config_path.exists():
        console.print(f"[yellow]⚠ Config file not found: {config_path}. Using defaults.[/]")
        return _default_config()

    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict):
            console.print("[yellow]⚠ Invalid config.yaml. Using defaults.[/]")
            return _default_config()
        return config
    except yaml.YAMLError as e:
        console.print(f"[red]✘ YAML parse error in config.yaml: {e}[/]")
        return _default_config()
    except OSError as e:
        console.print(f"[red]✘ Cannot read config.yaml: {e}[/]")
        return _default_config()


def _default_config() -> Dict[str, Any]:
    """Default configuration when config.yaml is missing/invalid."""
    return {
        "profiles": {
            "quick": {
                "description": "Fast recon-only scan",
                "phases": ["recon"],
                "recon_tasks": ["nuclei"],
                "fuzzing": {"enabled": False},
                "sniper": {"enabled": False},
                "timeout_minutes": 15,
            },
            "full": {
                "description": "Comprehensive scan",
                "phases": ["recon", "fuzzing", "sniper"],
                "recon_tasks": ["subfinder", "httpx", "nuclei"],
                "fuzzing": {"enabled": True, "vuln_types": ["xss", "sqli"], "max_iterations": 3},
                "sniper": {"enabled": True, "feeds": ["github"]},
                "timeout_minutes": 120,
            },
        },
        "display": {
            "refresh_interval": 2,
            "max_events": 50,
            "max_activities": 8,
            "max_errors": 20,
            "show_tool_summaries": True,
            "show_queue_status": True,
            "error_panel": True,
            "verbose": False,
            "hacker_theme": True,
            "show_banner": True,
        },
        "redis": {
            "host": "127.0.0.1",
            "port": 6379,
            "db": 0,
            "password": None,
            "socket_timeout": 5,
            "max_retries": 3,
            "retry_delay": 2,
        },
        "processes": {},
        "state": {
            "save_directory": ".jarvis_state",
            "auto_save_interval": 30,
            "max_state_files": 20,
            "fallback_directory": "/tmp/jarvis_state",
        },
    }


# ── Signal Handlers ───────────────────────────────────────────────────

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully."""
    global scan_controller, process_manager, state_manager

    console.print("\n[yellow]⚠ Interrupt received. Shutting down gracefully...[/]")
    shutdown_event.set()

    # Save state if scan is running
    if scan_controller and state_manager:
        scan_controller.status = "PAUSED"
        try:
            state = scan_controller.get_full_state()
            saved = state_manager.save_state(scan_controller.scan_id, state)
            if saved:
                console.print(
                    f"\n[green]✔ Scan state saved.[/] "
                    f"Resume with: [bold cyan]python -m cli.main --resume {scan_controller.scan_id}[/]"
                )
            else:
                console.print("[red]✘ Failed to save scan state.[/]")
        except Exception as e:
            console.print(f"[red]✘ Error saving state: {e}[/]")

    # Stop background processes
    if process_manager:
        try:
            process_manager.stop_all(timeout=10)
        except Exception as e:
            console.print(f"[red]✘ Error stopping processes: {e}[/]")

    # Stop scan controller
    if scan_controller:
        try:
            scan_controller.stop()
        except Exception:
            pass

    # Stop auto-save
    if state_manager:
        try:
            state_manager.stop_auto_save()
        except Exception:
            pass


# ── CLI Argument Parsing ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="centaur-jarvis",
        description="Centaur-Jarvis: AI-Powered VAPT Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m cli.main --target https://example.com
  python -m cli.main --target https://example.com --profile full
  python -m cli.main --target targets.txt
  python -m cli.main --resume SCAN_12345678
  python -m cli.main --target https://example.com --manual --verbose
  python -m cli.main --list-profiles
  python -m cli.main --list-scans
        """,
    )

    # Target specification
    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "--target", "-t",
        type=str,
        help="Target URL, comma-separated URLs, or file containing URLs",
    )
    target_group.add_argument(
        "--resume", "-r",
        type=str,
        metavar="SCAN_ID",
        help="Resume a previously paused scan by ID",
    )

    # Scan configuration
    scan_group = parser.add_argument_group("Scan Configuration")
    scan_group.add_argument(
        "--profile", "-p",
        type=str,
        default="quick",
        help="Scan profile: quick, full, recon_only, custom (default: quick)",
    )
    scan_group.add_argument(
        "--scan-id",
        type=str,
        default=None,
        help="Custom scan ID (auto-generated if not specified)",
    )

    # Mode flags
    mode_group = parser.add_argument_group("Modes")
    mode_group.add_argument(
        "--manual", "-m",
        action="store_true",
        help="Manual mode: assume services are already running",
    )
    mode_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose mode: show more detailed events",
    )
    mode_group.add_argument(
        "--no-display",
        action="store_true",
        help="Disable live dashboard (run headless)",
    )

    # Information
    info_group = parser.add_argument_group("Information")
    info_group.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available scan profiles and exit",
    )
    info_group.add_argument(
        "--list-scans",
        action="store_true",
        help="List saved scan states and exit",
    )

    return parser


# ── Command Handlers ──────────────────────────────────────────────────

def handle_list_profiles(config: Dict[str, Any]):
    """Display available scan profiles."""
    profiles = config.get("profiles", {})

    if HAS_RICH:
        from rich.table import Table
        from rich import box

        table = Table(
            title="📋 Available Scan Profiles",
            box=box.ROUNDED,
            border_style="cyan",
        )
        table.add_column("Profile", style="bold cyan")
        table.add_column("Description")
        table.add_column("Phases", style="green")
        table.add_column("Recon Tools", style="yellow")
        table.add_column("Fuzzing", style="magenta")
        table.add_column("Sniper", style="red")

        for name, cfg in profiles.items():
            phases = ", ".join(cfg.get("phases", []))
            tools = ", ".join(cfg.get("recon_tasks", []))
            fuzzing = "✔" if cfg.get("fuzzing", {}).get("enabled") else "✘"
            sniper = "✔" if cfg.get("sniper", {}).get("enabled") else "✘"
            desc = cfg.get("description", "No description")
            table.add_row(name, desc, phases, tools, fuzzing, sniper)

        console.print(table)
    else:
        print("\nAvailable Profiles:")
        for name, cfg in profiles.items():
            print(f"  {name}: {cfg.get('description', 'N/A')}")
            print(f"    Phases: {cfg.get('phases', [])}")


def handle_list_scans(config: Dict[str, Any]):
    """Display saved scan states."""
    state_cfg = config.get("state", {})
    sm = StateManager(
        save_directory=state_cfg.get("save_directory", ".jarvis_state"),
        fallback_directory=state_cfg.get("fallback_directory", "/tmp/jarvis_state"),
    )
    scans = sm.list_saved_scans()

    if not scans:
        console.print("[yellow]No saved scans found.[/]")
        return

    if HAS_RICH:
        from rich.table import Table
        from rich import box

        table = Table(
            title="💾 Saved Scans",
            box=box.ROUNDED,
            border_style="cyan",
        )
        table.add_column("Scan ID", style="bold cyan")
        table.add_column("Saved At")
        table.add_column("Size", style="dim")

        for scan in scans:
            table.add_row(
                scan["scan_id"],
                scan["saved_at"],
                f"{scan['size_kb']} KB",
            )

        console.print(table)
        console.print("\n[dim]Resume with: python -m cli.main --resume <SCAN_ID>[/]")
    else:
        print("\nSaved Scans:")
        for scan in scans:
            print(f"  {scan['scan_id']} (saved: {scan['saved_at']}, {scan['size_kb']} KB)")


# ── Main Scan Flow ────────────────────────────────────────────────────

def run_scan(args, config: Dict[str, Any]):
    """Main scan execution flow."""
    global scan_controller, process_manager, state_manager

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ── Resolve profile ──
    profile_name = args.profile
    profiles = config.get("profiles", {})

    if profile_name not in profiles:
        console.print(
            f"[yellow]⚠ Profile '{profile_name}' not found. "
            f"Available: {list(profiles.keys())}. Falling back to 'quick'.[/]"
        )
        profile_name = "quick"
        if profile_name not in profiles:
            profile_name = list(profiles.keys())[0] if profiles else "quick"

    profile_config = profiles.get(profile_name, _default_config()["profiles"]["quick"])
    display_config = config.get("display", _default_config()["display"])
    redis_config = config.get("redis", _default_config()["redis"])
    state_config = config.get("state", _default_config()["state"])

    if args.verbose:
        display_config["verbose"] = True

    # ── Initialize State Manager ──
    state_manager = StateManager(
        save_directory=state_config.get("save_directory", ".jarvis_state"),
        fallback_directory=state_config.get("fallback_directory", "/tmp/jarvis_state"),
        auto_save_interval=state_config.get("auto_save_interval", 30),
        max_state_files=state_config.get("max_state_files", 20),
    )

    # ── Initialize Process Manager ──
    process_manager = ProcessManager(
        config=config,
        manual_mode=args.manual,
    )

    # Check for duplicate instances
    if not args.manual and process_manager.check_duplicate_instance():
        console.print(
            "[red]✘ Another Centaur-Jarvis instance is already running.[/]\n"
            "[dim]Kill it first or use --manual mode.[/]"
        )
        sys.exit(1)

    # ── Initialize Scan Controller ──
    scan_controller = ScanController(
        config=config,
        logger=None, # Using None for now, can be replaced with a proper logger if needed
    )


    # ── Resume or New Scan ──
    if args.resume:
        console.print(f"[cyan]Resuming scan: {args.resume}[/]")
        saved_state = state_manager.load_state(args.resume)
        if not saved_state:
            console.print(f"[red]✘ No saved state found for scan '{args.resume}'[/]")
            console.print("[dim]Use --list-scans to see available scans.[/]")
            sys.exit(1)

        if not scan_controller.restore_from_state(saved_state):
            console.print("[red]✘ Failed to restore scan state. Check Redis connection.[/]")
            sys.exit(1)

        profile_name = scan_controller.profile_name
        profile_config = profiles.get(profile_name, profile_config)

    else:
        # New scan
        if not args.target:
            console.print("[red]✘ No target specified. Use --target or --resume.[/]")
            console.print("[dim]Run with --help for usage information.[/]")
            sys.exit(1)

        if not scan_controller.initialize_scan(
            target_input=args.target,
            profile_name=profile_name,
            scan_id=args.scan_id,
        ):
            console.print("[red]✘ Scan initialization failed. Check errors above.[/]")
            # Show accumulated errors
            for err in scan_controller.errors.get_all():
                console.print(f"  [red]✘ {err.get('message')}[/]")
            sys.exit(1)

    # ── Start Background Services (non-manual mode) ──
    if not args.manual:
        phases = profile_config.get("phases", ["recon"])
        console.print("[cyan]Starting background services...[/]")
        service_results = process_manager.start_services(required_phases=phases)

        # Check if required services failed
        for svc_name, svc_status in service_results.items():
            if svc_status == "FAILED":
                proc_cfg = config.get("processes", {}).get(svc_name, {})
                if proc_cfg.get("required", False):
                    console.print(
                        f"[red]✘ Required service '{svc_name}' failed to start.[/]\n"
                        f"[dim]Try --manual mode if services are running externally.[/]"
                    )
                    process_manager.stop_all()
                    sys.exit(1)
                else:
                    console.print(f"[yellow]⚠ Optional service '{svc_name}' failed to start.[/]")
    else:
        console.print("[yellow]Manual mode: assuming services are already running.[/]")

    # ── Start Auto-Save ──
    state_manager.start_auto_save(
        scan_id=scan_controller.scan_id,
        state_getter=scan_controller.get_full_state,
    )

    # ── Initialize Display ──
    display = LiveDisplay(
        scan_controller=scan_controller,
        display_config=display_config,
        verbose=args.verbose,
    )

    # ── Run Scan in Background Thread ──
    scan_thread = threading.Thread(
        target=_run_scan_thread,
        args=(scan_controller,),
        daemon=True,
        name="scan-main",
    )
    scan_thread.start()

    # ── Start health check thread
    def _health_check_loop():
        while not scan_controller._stop_event.is_set():
            process_manager.health_check(scan_controller)
            time.sleep(30)  # check every 30 seconds

    health_thread = threading.Thread(target=_health_check_loop, daemon=True)
    health_thread.start()

    # ── Start Live Display (blocks until shutdown) ──
    if not args.no_display:
        try:
            display.start(stop_event=shutdown_event)
        except KeyboardInterrupt:
            shutdown_event.set()
    else:
        # Headless mode: just wait for scan to complete
        console.print("[dim]Running headless (no display). Press Ctrl+C to stop.[/]")
        try:
            while not shutdown_event.is_set():
                if scan_controller.status in ("COMPLETED", "FAILED"):
                    shutdown_event.set()
                    break
                shutdown_event.wait(timeout=2)
        except KeyboardInterrupt:
            shutdown_event.set()

    # ── Wait for scan thread to finish ──
    scan_thread.join(timeout=10)

    # ── Final Summary ──
    display.print_summary()

    # ── Cleanup ──
    state_manager.stop_auto_save()

    if scan_controller.status == "COMPLETED":
        # Clean up saved state on completion
        state_manager.delete_state(scan_controller.scan_id)
    elif scan_controller.status == "PAUSED":
        # State already saved by signal handler
        console.print(
            f"\n[yellow]Scan paused.[/] "
            f"Resume: [bold cyan]python -m cli.main --resume {scan_controller.scan_id}[/]"
        )

    if not args.manual:
        process_manager.stop_all()

    # Clean PID file
    if not args.manual:
        pid_file = ProcessManager.PID_DIR / "cli_master.pid"
        try:
            pid_file.unlink(missing_ok=True)
        except OSError:
            pass

    # Exit code based on status
    exit_code = 0 if scan_controller.status == "COMPLETED" else 1
    sys.exit(exit_code)


def _run_scan_thread(controller: ScanController):
    """Run the scan in a background thread."""
    global shutdown_event
    try:
        controller.run_scan()
    except Exception as e:
        controller._add_error(f"Scan thread crashed: {e}")
        controller.status = "FAILED"
    finally:
        if controller.status not in ("PAUSED",):
            # Give display time to show final state
            time.sleep(3)
            shutdown_event.set()


# ── Entry Point ───────────────────────────────────────────────────────

def main():
    """Main entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    # Show banner
    if HAS_RICH:
        console.print(f"[bold red]{BANNER_ART}[/]")
    else:
        print(BANNER_ART)

    # Load config
    config = load_config()

    # Handle info commands
    if args.list_profiles:
        handle_list_profiles(config)
        sys.exit(0)

    if args.list_scans:
        handle_list_scans(config)
        sys.exit(0)

    # Validate: need either target or resume
    if not args.target and not args.resume:
        parser.print_help()
        console.print("\n[red]✘ Specify --target or --resume to start.[/]")
        sys.exit(1)

    # Run the scan
    run_scan(args, config)


if __name__ == "__main__":
    main()
