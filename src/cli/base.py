"""CLI base components for RETRO-Ollama."""

from typing import Optional

from rich.console import Console
from rich.panel import Panel

console = Console()

BANNER_SKULL = """
   ───▐▀▄──────▄▀▌───▄▄▄▄▄▄▄
───▌▒▒▀▄▄▄▄▀▒▒▐▄▀▀▒██▒██▒▀▀▄
──▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄
──▌▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▀▄
▀█▒▒█▌▒▒█▒▒▐█▒▒▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌
▀▌▒▒▒▒▒▀▒▀▒▒▒▒▒▀▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐ ▄▄
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄█▒█
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▀
───▐▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▌
─────▀▄▄▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀

  [ {mode_name} ]   {mode_desc}
 ============================================================
        +++ Powered by Local AI Models +++
        (Ollama, LM Studio, Llama.cpp)
 ============================================================
"""


def print_banner(show_mode: bool = True) -> None:
    """Print the application banner."""
    from src.modes import get_current_mode, get_mode_info
    
    if show_mode:
        current = get_current_mode()
        mode_info = get_mode_info(current)
        console.print(BANNER_SKULL.format(
            mode_name=mode_info['name'],
            mode_desc=mode_info['description']
        ))
    else:
        console.print(BANNER_SKULL.format(
            mode_name="RETRO-OLLAMA",
            mode_desc="Pentesting AI Tool"
        ))
    console.print()


def print_status(current_model: Optional[str] = None, output_dir: str = "./output") -> None:
    """Print current status panel."""
    from src.modes import get_current_mode, get_mode_info
    from rich import box
    
    current = get_current_mode()
    mode_info = get_mode_info(current)
    mode_color = mode_info.get('color', '#808080')
    mode_icon = mode_info.get('icon', '')
    
    console.print(Panel(
        f" Mode: {mode_info['name']}   |   "
        f"Model: {current_model or 'N/A'}   |   "
        f"Output: {output_dir}",
        border_style=mode_color,
        box=box.ROUNDED,
        padding=(0, 1),
        title=f"[{mode_color}][{mode_icon}] MODO ACTUAL[/]"
    ))
    console.print()


def print_error(message: str) -> None:
    """Print error message."""
    console.print(f"[red]✗ {message}[/red]")


def print_success(message: str) -> None:
    """Print success message."""
    console.print(f"[green]✓ {message}[/green]")


def print_warning(message: str) -> None:
    """Print warning message."""
    console.print(f"[yellow]⚠ {message}[/yellow]")


def print_info(message: str) -> None:
    """Print info message."""
    console.print(f"[cyan]ℹ {message}[/cyan]")
