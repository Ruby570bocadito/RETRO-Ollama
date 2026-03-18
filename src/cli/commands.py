"""CLI commands using Typer for RETRO-Ollama."""

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from src.cli.base import print_success, print_error, print_info
from src.config import get_config

app = typer.Typer(help="RETRO-Ollama CLI Commands")
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target to scan"),
    type: str = typer.Option("quick", "--type", "-t", help="Scan type"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Ports to scan"),
    stealth: bool = typer.Option(False, "--stealth", "-s", help="Use stealth mode"),
) -> None:
    """Run a scan on a target."""
    from src.tools.pentest import quick_scan, full_scan, vuln_scan, web_scan, stealth_scan
    
    print_info(f"Starting {type} scan on {target}")
    
    scan_functions = {
        "quick": quick_scan,
        "full": full_scan,
        "vuln": vuln_scan,
        "web": web_scan,
        "stealth": stealth_scan,
    }
    
    scan_func = scan_functions.get(type, quick_scan)
    
    try:
        result = scan_func(target)
        print_success(f"Scan completed: {result.get('status', 'unknown')}")
    except Exception as e:
        print_error(f"Scan failed: {e}")


@app.command()
def mode(
    mode_name: Optional[str] = typer.Argument(None, help="Mode to switch to"),
) -> None:
    """Show or change mode."""
    from src.modes import get_current_mode, set_mode, list_modes
    
    if mode_name is None:
        current = get_current_mode()
        print_info(f"Current mode: {current}")
        return
    
    set_mode(mode_name)
    print_success(f"Mode changed to: {mode_name}")


@app.command()
def modes() -> None:
    """List all available modes."""
    from src.modes import list_modes, MODES
    
    table = Table(title="Available Modes")
    table.add_column("Mode", style="cyan")
    table.add_column("Description", style="white")
    
    for mode_key, mode_data in MODES.items():
        table.add_row(mode_key, mode_data.get("description", ""))
    
    console.print(table)


@app.command()
def config(
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    list_keys: bool = typer.Option(False, "--keys", help="List API keys status"),
) -> None:
    """Show configuration."""
    cfg = get_config()
    
    if show:
        console.print("[bold]Current Configuration:[/bold]")
        console.print(f"Ollama Host: {cfg.ollama.host}")
        console.print(f"Default Model: {cfg.ollama.default_model}")
        console.print(f"Timeout: {cfg.ollama.timeout}s")
    
    if list_keys:
        from src.config.settings import check_api_keys
        keys = check_api_keys()
        
        table = Table(title="API Keys Status")
        table.add_column("Service", style="cyan")
        table.add_column("Status", style="white")
        
        for service, configured in keys.items():
            status = "[green]✓ Configured[/green]" if configured else "[red]✗ Not configured[/red]"
            table.add_row(service, status)
        
        console.print(table)


@app.command()
def health() -> None:
    """Run health checks."""
    from src.health import run_health_checks
    
    print_info("Running health checks...")
    results = run_health_checks()
    
    status_color = {
        "healthy": "green",
        "degraded": "yellow",
        "unhealthy": "red",
    }
    
    console.print(f"\n[bold]Overall Status:[/bold] [{status_color[results['status']]}]{results['status']}[/]")
    
    table = Table(title="Health Checks")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Message", style="dim")
    
    for check in results["checks"]:
        color = status_color.get(check["status"], "white")
        table.add_row(
            check["name"],
            f"[{color}]{check['status']}[/]",
            check["message"],
        )
    
    console.print(table)


@app.command()
def metrics(
    summary: bool = typer.Option(True, "--summary", help="Show summary"),
    dashboard: bool = typer.Option(False, "--dashboard", help="Show dashboard"),
    days: int = typer.Option(7, "--days", "-d", help="Days to show"),
) -> None:
    """Show metrics."""
    from src.metrics import metrics_collector
    
    if dashboard:
        data = metrics_collector.get_dashboard_data()
        console.print("[bold]Dashboard:[/bold]")
        console.print(f"Daily Scans: {data['daily_scans']}")
        console.print(f"Daily Findings: {data['daily_findings']}")
    else:
        summary_data = metrics_collector.get_summary()
        
        table = Table(title=f"Metrics (Last {days} days)")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        for key, value in summary_data.items():
            if isinstance(value, dict):
                continue
            table.add_row(key, str(value))
        
        console.print(table)


@app.command()
def cache(
    clear: bool = typer.Option(False, "--clear", help="Clear cache"),
    stats: bool = typer.Option(False, "--stats", help="Show cache stats"),
) -> None:
    """Manage cache."""
    from src.cache import api_cache
    
    if stats:
        stats_data = api_cache.get_stats()
        
        table = Table(title="Cache Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Disk Entries", str(stats_data["disk_entries"]))
        table.add_row("Memory Entries", str(stats_data["memory_entries"]))
        table.add_row("Total Size", f"{stats_data['total_size_bytes'] / 1024:.2f} KB")
        
        console.print(table)
    
    if clear:
        count = api_cache.clear_all()
        print_success(f"Cleared {count} cache entries")


@app.command()
def version() -> None:
    """Show version information."""
    console.print("[bold]RETRO-Ollama v2.0.0[/bold]")
    console.print("Autonomous Pentesting AI Tool")
    console.print("Powered by Local AI Models (Ollama, LM Studio, Llama.cpp)")


@app.command()
def exit() -> None:
    """Exit the application."""
    raise typer.Exit()


if __name__ == "__main__":
    app()
