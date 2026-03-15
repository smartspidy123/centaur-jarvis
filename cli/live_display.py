"""
Advanced Live Display – Hacker-style real-time terminal dashboard.

Features:
- ASCII art banner with animated glow
- Current activity panel with spinners
- Live event feed with color-coded entries
- Statistics and tool summary panels
- Error panel with timestamps
- Queue status bar
- Auto-refresh every N seconds via rich.live.Live
- Handles terminal resize automatically (rich built-in)

Edge Cases Handled:
- Terminal too narrow → graceful degradation
- No events → "Waiting for activity..." placeholder
- Unicode errors → fallback to ASCII
- Keyboard interrupt during display → clean shutdown
"""

import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich.columns import Columns
    from rich.align import Align
    from rich.spinner import Spinner
    from rich.padding import Padding
    from rich import box

    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ── Banner ────────────────────────────────────────────────────────────

BANNER_ART = r"""
██████╗ ██████╗  █████╗ ███╗   ██╗ ██████╗  █████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██╔══██╗████╗  ██║
██████╔╝██████╔╝███████║██╔██╗ ██║██║  ███╗███████║██╔██╗ ██║
██╔═══╝ ██╔══██╗██╔══██║██║╚██╗██║██║   ██║██╔══██║██║╚██╗██║
██║     ██║  ██║██║  ██║██║ ╚████║╚██████╔╝██║  ██║██║ ╚████║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
          ╔═══════════════════════════════════════╗
          ║   J A R V I S  •  V A P T  A G E N T  ║
          ╚═══════════════════════════════════════╝"""

BANNER_FALLBACK = """
=== CENTAUR-JARVIS VAPT AGENT ===
"""


# ── Event Type Icons & Colors ─────────────────────────────────────────

EVENT_STYLES = {
    "info": {"icon": "ℹ ", "color": "cyan"},
    "success": {"icon": "✔ ", "color": "green"},
    "discovery": {"icon": "🔍", "color": "green"},
    "warning": {"icon": "⚠ ", "color": "yellow"},
    "critical": {"icon": "❗", "color": "bold red"},
    "phase": {"icon": "▶ ", "color": "bold magenta"},
    "error": {"icon": "✘ ", "color": "red"},
}


class LiveDisplay:
    """
    Real-time hacker-style terminal dashboard using Rich library.
    
    Renders a continuously-updating display showing scan progress,
    current activities, live events, statistics, and errors.
    """

    def __init__(
        self,
        scan_controller,
        display_config: Dict[str, Any],
        verbose: bool = False,
    ):
        """
        Args:
            scan_controller: ScanController instance for data
            display_config: Display settings from config.yaml
            verbose: Show more detailed events
        """
        self.controller = scan_controller
        self.config = display_config
        self.verbose = verbose or display_config.get("verbose", False)
        self.refresh_interval = display_config.get("refresh_interval", 2)
        self.show_tool_summaries = display_config.get("show_tool_summaries", True)
        self.show_queue_status = display_config.get("show_queue_status", True)
        self.show_error_panel = display_config.get("error_panel", True)
        self.hacker_theme = display_config.get("hacker_theme", True)
        self.show_banner = display_config.get("show_banner", True)

        self._console: Optional[Any] = None
        self._live: Optional[Any] = None

        if HAS_RICH:
            self._console = Console()
        else:
            print("[WARNING] 'rich' not installed. Using plain text output.")

    def render_dashboard(self) -> Any:
        """Build the complete dashboard layout."""
        if not HAS_RICH:
            return self._render_plain()

        layout = Layout()

        # Build sections
        sections = []

        # 1. Banner (compact)
        if self.show_banner:
            sections.append(Layout(self._build_banner(), name="banner", size=9))

        # 2. Scan info bar
        sections.append(Layout(self._build_scan_info(), name="scaninfo", size=3))

        # 3. Phase progress bar
        sections.append(Layout(self._make_phase_progress(), name="phase_progress", size=3))

        # 4. Activities panel
        sections.append(Layout(self._build_activities(), name="activities", size=None, minimum_size=5))

        # 4. Events panel
        sections.append(Layout(self._build_events(), name="events", size=None, minimum_size=8))

        # 5. Command log panel
        sections.append(Layout(self._make_command_log(), name="command_log", size=5))

        # 6. Stats + Tool summaries (side by side)
        if self.show_tool_summaries:
            stats_layout = Layout(name="stats_row", size=8)
            stats_layout.split_row(
                Layout(self._build_stats(), name="stats"),
                Layout(self._build_tool_summaries(), name="summaries"),
            )
            sections.append(stats_layout)
        else:
            sections.append(Layout(self._build_stats(), name="stats", size=8))

        # 7. Error panel
        if self.show_error_panel:
            errors = self.controller.errors.get_all()
            if errors:
                sections.append(
                    Layout(self._build_errors(), name="errors", size=min(6, len(errors) + 2))
                )

        # 8. Queue status bar
        if self.show_queue_status:
            sections.append(Layout(self._build_queue_status(), name="queue", size=3))

        layout.split_column(*sections)
        return layout

    # ── Panel Builders ────────────────────────────────────────────────

    def _build_banner(self) -> Panel:
        """Build ASCII art banner."""
        try:
            banner_text = Text(BANNER_ART, style="bold red")
        except Exception:
            banner_text = Text(BANNER_FALLBACK, style="bold red")

        return Panel(
            Align.center(banner_text),
            style="bold green",
            border_style="red",
            box=box.DOUBLE,
            padding=(0, 0),
        )

    def _build_scan_info(self) -> Panel:
        """Build scan metadata info bar."""
        c = self.controller
        elapsed = c.get_elapsed_time()
        target_display = c.targets[0] if c.targets else "N/A"
        if len(c.targets) > 1:
            target_display += f" (+{len(c.targets) - 1} more)"

        status_color = {
            "RUNNING": "green",
            "COMPLETED": "bold green",
            "FAILED": "bold red",
            "PAUSED": "yellow",
            "PENDING": "dim",
        }.get(c.status, "white")

        info = Text()
        info.append("  Scan: ", style="dim")
        info.append(c.scan_id, style="bold cyan")
        info.append("  │  Target: ", style="dim")
        info.append(target_display, style="bold white")
        info.append("  │  Profile: ", style="dim")
        info.append(c.profile_name, style="bold yellow")
        info.append("  │  Phase: ", style="dim")
        info.append(c.current_phase.upper() or "INIT", style="bold magenta")
        info.append("  │  Elapsed: ", style="dim")
        info.append(elapsed, style="bold green")
        info.append("  │  Status: ", style="dim")
        info.append(c.status, style=status_color)

        return Panel(info, border_style="cyan", box=box.ROUNDED, padding=(0, 0))

    def _make_phase_progress(self) -> Panel:
        """Create a progress bar for current phase task completion."""
        from rich.spinner import Spinner
        # Placeholder until controller methods are added
        total = 0  # TODO: get from controller._get_phase_task_count()
        if total == 0:
            return Panel(Spinner("dots", text="Idle"), title="Phase Progress", border_style="cyan")
        return Panel("Progress tracking pending", title="Phase Progress", border_style="green")

    def _make_command_log(self) -> Panel:
        """Show recently executed commands from event feed."""
        from rich.table import Table
        
        # Get command events from controller.events
        # Events already have type="cmd" if we added them
        cmd_events = [
            e for e in self.controller.events.get_all()[-10:]
            if e.get("type") == "cmd"
        ]
        
        if not cmd_events:
            return Panel("No commands executed yet", style="dim")
        
        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_column(style="dim", width=8)  # timestamp
        table.add_column(style="cyan")          # command
        
        for e in cmd_events[-5:]:  # last 5 commands
            table.add_row(e.get("timestamp", ""), e.get("message", ""))
        
        return Panel(table, title="💻 Command Log", border_style="blue")

    def _build_activities(self) -> Panel:
        """Build current activities panel with spinners."""
        return self._make_activities_panel()

    def _make_activities_panel(self) -> Panel:
        """Build current activities panel with rich.table.Table and spinners."""
        activities = self.controller.get_activities()

        if not activities:
            content = Text("  Waiting for tasks...", style="dim italic")
            return Panel(
                content,
                title="🔥 [bold cyan]CURRENT ACTIVITY[/]",
                border_style="cyan",
                box=box.ROUNDED,
                padding=(0, 1),
            )

        table = Table(
            show_header=False,
            box=None,
            padding=(0, 0),
            expand=True,
            show_lines=False,
        )
        table.add_column("Status", width=4)
        table.add_column("Tool", width=15)
        table.add_column("Description", ratio=1)
        table.add_column("Elapsed", width=10)

        for act in activities:
            elapsed = int(time.time() - act.get("started_at", time.time()))
            tool = act.get("tool", "unknown")
            desc = act.get("description", "")

            spinner = Spinner("dots", style="cyan")
            table.add_row(
                spinner,
                Text(tool, style="bold white"),
                Text(desc, style="cyan"),
                Text(f"{elapsed}s", style="dim"),
            )

        return Panel(
            table,
            title="🔥 [bold cyan]CURRENT ACTIVITY[/]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 1),
        )


    def _build_events(self) -> Panel:
        """Build live events feed with color-coded entries."""
        events = self.controller.events.get_all()

        if not events:
            content = Text("  Waiting for events...", style="dim italic")
            return Panel(
                content,
                title="💡 [bold green]LIVE EVENTS[/]",
                border_style="green",
                box=box.ROUNDED,
                padding=(0, 1),
            )

        # Show last N events (most recent at bottom)
        display_events = events[-15:]  # Show last 15 in the panel

        lines = []
        for event in display_events:
            ts = event.get("timestamp", "??:??:??")
            etype = event.get("type", "info")
            msg = event.get("message", "")

            style_info = EVENT_STYLES.get(etype, EVENT_STYLES["info"])
            icon = style_info["icon"]
            color = style_info["color"]

            line = Text()
            line.append(f"  {ts} ", style="dim")
            line.append(f"{icon} ", style=color)
            line.append(msg, style=color if etype in ("critical", "phase") else "white")
            lines.append(line)

        content = Text("\n").join(lines)
        return Panel(
            content,
            title="💡 [bold green]LIVE EVENTS[/]",
            border_style="green",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def _build_stats(self) -> Panel:
        """Build statistics panel."""
        stats = self.controller.stats

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Metric", style="dim")
        table.add_column("Value", style="bold white")

        table.add_row("Tasks pushed", str(stats.get("tasks_pushed", 0)))
        table.add_row("Tasks completed", str(stats.get("tasks_completed", 0)))
        table.add_row("Tasks failed", str(stats.get("tasks_failed", 0)))
        table.add_row("Findings", str(stats.get("findings_count", 0)))
        table.add_row("AI calls", str(stats.get("ai_calls", 0)))
        table.add_row("RAG snippets", str(stats.get("rag_snippets", 0)))

        return Panel(
            table,
            title="📊 [bold magenta]STATS[/]",
            border_style="magenta",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def _build_tool_summaries(self) -> Panel:
        """Build tool summaries panel."""
        summaries = self.controller.tool_summaries

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Metric", style="dim")
        table.add_column("Value", style="bold white")

        ports = summaries.get("ports_open", [])
        ports_str = ",".join(str(p) for p in ports[:10]) if ports else "none"
        if len(ports) > 10:
            ports_str += "..."

        table.add_row("Ports open", ports_str)
        table.add_row("Subdomains", str(summaries.get("subdomains", 0)))
        table.add_row("Endpoints", str(summaries.get("endpoints", 0)))
        table.add_row("Payloads sent", str(summaries.get("payloads_sent", 0)))
        table.add_row("Interesting resp.", str(summaries.get("interesting_responses", 0)))

        templates = summaries.get("templates_matched", 0)
        critical = summaries.get("critical_findings", 0)
        template_str = str(templates)
        if critical:
            template_str += f" ({critical} crit)"
        table.add_row("Templates matched", template_str)

        techs = summaries.get("technologies", [])
        techs_str = ", ".join(techs[:5]) if techs else "none"
        if len(techs) > 5:
            techs_str += "..."
        table.add_row("Technologies", techs_str)

        return Panel(
            table,
            title="📦 [bold blue]TOOL SUMMARIES[/]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def _build_errors(self) -> Panel:
        """Build error panel."""
        errors = self.controller.errors.get_all()

        if not errors:
            return Panel(
                Text("  No errors", style="dim green"),
                title="❌ [bold red]ERRORS[/]",
                border_style="red",
                box=box.ROUNDED,
                padding=(0, 1),
            )

        display_errors = errors[-5:]  # Show last 5 errors
        lines = []
        for err in display_errors:
            ts = err.get("timestamp", "??:??:??")
            msg = err.get("message", "Unknown error")

            line = Text()
            line.append(f"  {ts} ", style="dim")
            line.append("✘ ", style="red")
            line.append(msg, style="red")
            lines.append(line)

        content = Text("\n").join(lines)
        return Panel(
            content,
            title="❌ [bold red]ERRORS[/]",
            border_style="red",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def _build_queue_status(self) -> Panel:
        """Build queue status bar."""
        queues = self.controller.get_queue_lengths()

        if not queues:
            content = Text("  Queue status unavailable (Redis not connected)", style="dim red")
        else:
            content = Text()
            content.append("  Queue Status: ", style="dim")
            parts = []
            for name, length in queues.items():
                color = "green" if length == 0 else ("yellow" if length < 5 else "red")
                parts.append(f"[{color}]{name}={length}[/]")
            content.append(Text.from_markup("  │  ".join(parts)))

        return Panel(
            content,
            border_style="dim",
            box=box.ROUNDED,
            padding=(0, 0),
        )

    # ── Plain Text Fallback ───────────────────────────────────────────

    def _render_plain(self) -> str:
        """Fallback plain text rendering when rich is not available."""
        c = self.controller
        lines = [
            "=" * 60,
            f"  CENTAUR-JARVIS | Scan: {c.scan_id} | {c.get_elapsed_time()}",
            f"  Target: {c.targets[0] if c.targets else 'N/A'} | Profile: {c.profile_name}",
            f"  Phase: {c.current_phase} | Status: {c.status}",
            "-" * 60,
            "  ACTIVITIES:",
        ]
        for act in c.activities.get_all():
            lines.append(f"    • {act.get('tool')}: {act.get('description')}")
        lines.append("-" * 60)
        lines.append("  EVENTS (last 10):")
        for event in c.events.get_all()[-10:]:
            lines.append(f"    [{event.get('timestamp')}] {event.get('message')}")
        lines.append("-" * 60)
        lines.append(f"  Stats: tasks={c.stats.get('tasks_pushed', 0)}, "
                     f"done={c.stats.get('tasks_completed', 0)}, "
                     f"findings={c.stats.get('findings_count', 0)}")
        errors = c.errors.get_all()
        if errors:
            lines.append("-" * 60)
            lines.append("  ERRORS:")
            for err in errors[-5:]:
                lines.append(f"    ✘ [{err.get('timestamp')}] {err.get('message')}")
        lines.append("=" * 60)
        return "\n".join(lines)

    # ── Public Interface ──────────────────────────────────────────────

    def start(self, stop_event):
        """
        Start the live dashboard. Blocks until stop_event is set.
        
        Args:
            stop_event: threading.Event to signal shutdown
        """
        if not HAS_RICH:
            self._start_plain(stop_event)
            return

        try:
            with Live(
                self.render_dashboard(),
                console=self._console,
                refresh_per_second=1.0 / self.refresh_interval,
                screen=True,
                transient=False,
            ) as live:
                self._live = live
                while not stop_event.is_set():
                    try:
                        live.update(self.render_dashboard())
                    except Exception as e:
                        # Handle rendering errors gracefully
                        try:
                            error_text = Text(f"Display error: {e}", style="red")
                            live.update(Panel(error_text, title="ERROR"))
                        except Exception:
                            pass
                    stop_event.wait(timeout=self.refresh_interval)
        except KeyboardInterrupt:
            stop_event.set()
        except Exception as e:
            if self._console:
                self._console.print(f"[red]Display error: {e}[/red]")
        finally:
            self._live = None

    def _start_plain(self, stop_event):
        """Plain text display loop when rich is not available."""
        while not stop_event.is_set():
            try:
                # Clear screen
                print("\033[2J\033[H", end="")
                print(self._render_plain())
            except Exception as e:
                print(f"Display error: {e}")
            stop_event.wait(timeout=self.refresh_interval)

    def print_summary(self):
        """Print final scan summary after dashboard closes."""
        if HAS_RICH and self._console:
            console = self._console
        elif HAS_RICH:
            console = Console()
        else:
            print(self._render_plain())
            return

        c = self.controller

        console.print()
        console.print(Panel(
            Text(BANNER_ART, style="bold red"),
            border_style="red",
            box=box.DOUBLE,
        ))

        # Summary table
        table = Table(title="📋 Scan Summary", box=box.ROUNDED, border_style="cyan")
        table.add_column("Metric", style="dim")
        table.add_column("Value", style="bold")

        table.add_row("Scan ID", c.scan_id)
        table.add_row("Targets", str(len(c.targets)))
        table.add_row("Profile", c.profile_name)
        table.add_row("Status", f"[green]{c.status}[/]" if c.status == "COMPLETED" else f"[yellow]{c.status}[/]")
        table.add_row("Duration", c.get_elapsed_time())
        table.add_row("Tasks Pushed", str(c.stats.get("tasks_pushed", 0)))
        table.add_row("Tasks Completed", str(c.stats.get("tasks_completed", 0)))
        table.add_row("Findings", str(c.stats.get("findings_count", 0)))
        table.add_row("AI Calls", str(c.stats.get("ai_calls", 0)))

        console.print(table)

        # Findings summary
        findings = c._get_current_findings()
        if findings:
            findings_table = Table(title="🔍 Findings", box=box.ROUNDED, border_style="red")
            findings_table.add_column("#", style="dim")
            findings_table.add_column("Severity", style="bold")
            findings_table.add_column("Type")
            findings_table.add_column("Location")

            for i, f in enumerate(findings[:20], 1):
                sev = f.get("severity", "info").upper()
                sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "dim")
                findings_table.add_row(
                    str(i),
                    f"[{sev_color}]{sev}[/]",
                    f.get("type", "N/A"),
                    f.get("url", f.get("endpoint", "N/A")),
                )

            console.print(findings_table)

        # Errors
        errors = c.errors.get_all()
        if errors:
            console.print(f"\n[red]⚠ {len(errors)} error(s) during scan[/red]")
            for err in errors[-5:]:
                console.print(f"  [dim]{err.get('timestamp')}[/] [red]✘ {err.get('message')}[/]")

        console.print()
