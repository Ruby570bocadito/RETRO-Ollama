"""
PTAI CLI Theme — Custom Color Palette
Professional hacker-themed color scheme for the pentesting CLI.
"""

# ── Primary Colors ──────────────────────────────────────────────
PRIMARY = "#00FF88"       # Neon green — success, primary actions
PRIMARY_DIM = "#00CC6A"   # Dimmed green
SECONDARY = "#00D4FF"     # Cyan — secondary info, commands
ACCENT = "#FF6B35"        # Orange — warnings, scan categories
ACCENT_ALT = "#FFD93D"    # Yellow — generation categories

# ── Status Colors ───────────────────────────────────────────────
SUCCESS = "#00FF88"       # Green
ERROR = "#FF4757"         # Red
WARNING = "#FFD93D"       # Yellow
INFO = "#808080"          # Gray
INFO_LIGHT = "#A0A0A0"    # Light gray

# ── Text Hierarchy ─────────────────────────────────────────────
TEXT_PRIMARY = "#E8E8E8"  # Near-white for main text
TEXT_SECONDARY = "#A0A0A0"  # Gray for secondary
TEXT_DIM = "#606060"      # Dark gray for tertiary
TEXT_MUTED = "#404040"    # Very dark for borders, dividers

# ── Category Colors ────────────────────────────────────────────
CAT_SCAN = "#00D4FF"      # Cyan
CAT_GENERATE = "#FFD93D"  # Yellow
CAT_ENUM = "#FF6B35"      # Orange
CAT_UTILS = "#808080"     # Gray

# ── Mode Definitions (color + text symbol replacing emoji) ────
MODE_CONFIG = {
    "autonomous":    {"color": "#808080", "symbol": "[A]",  "label": "Autonomous"},
    "pentester":     {"color": "#FF6B35", "symbol": "[P]",  "label": "Pentester"},
    "blue":          {"color": "#00A8E8", "symbol": "[B]",  "label": "Blue Team"},
    "osint":         {"color": "#00FF88", "symbol": "[O]",  "label": "OSINT"},
    "forense":       {"color": "#9B59B6", "symbol": "[F]",  "label": "Forense"},
    "bugbounty":     {"color": "#F1C40F", "symbol": "[BB]", "label": "Bug Bounty"},
    "redteam":       {"color": "#E74C3C", "symbol": "[RT]", "label": "Red Team"},
    "vulnassessment":{"color": "#3498DB", "symbol": "[VA]", "label": "Vuln Assessment"},
    "network":       {"color": "#2ECC71", "symbol": "[N]",  "label": "Network"},
    "webapp":        {"color": "#9B59B6", "symbol": "[W]",  "label": "Web App"},
    "social":        {"color": "#E67E22", "symbol": "[SE]", "label": "Social Engineering"},
    "devsecops":     {"color": "#00CED1", "symbol": "[DS]", "label": "DevSecOps"},
    "malware":       {"color": "#DC143C", "symbol": "[M]",  "label": "Malware Analysis"},
    "iot":           {"color": "#FF8C00", "symbol": "[IoT]","label": "IoT Security"},
    "cloud":         {"color": "#4169E1", "symbol": "[C]",  "label": "Cloud Security"},
    "mobile":        {"color": "#32CD32", "symbol": "[Mob]","label": "Mobile Security"},
    "compliance":    {"color": "#FFD700", "symbol": "[Comp]","label": "Compliance"},
}

# ── Symbol Replacements for Emojis ─────────────────────────────
SYMBOLS = {
    "success":    "OK",
    "error":      "ERR",
    "warning":    "WARN",
    "info":       "INFO",
    "arrow_right": ">",
    "arrow_play": ">",
    "bullet":     "-",
    "bullet_small": "·",
    "loading":    "...",
    "target":     "[T]",
    "scan":       "[S]",
    "shield":     "[SH]",
    "search":     "[?]",
    "code":       "[C]",
    "terminal":   ">",
    "clock":      "[T]",
    "document":   "[D]",
    "check":      "OK",
    "cross":      "X",
}


def fmt(text: str, color: str) -> str:
    """Wrap text in Rich color tags."""
    return f"[{color}]{text}[/{color}]"


def bold(text: str, color: str = TEXT_PRIMARY) -> str:
    """Bold colored text."""
    return f"[bold {color}]{text}[/bold {color}]"


def dim(text: str) -> str:
    """Dimmed text."""
    return f"[dim]{text}[/dim]"


def status_ok(text: str) -> str:
    """Success status line."""
    return f"[{SUCCESS}]OK {text}[/{SUCCESS}]"


def status_err(text: str) -> str:
    """Error status line."""
    return f"[{ERROR}]ERR {text}[/{ERROR}]"


def status_warn(text: str) -> str:
    """Warning status line."""
    return f"[{WARNING}]WARN {text}[/{WARNING}]"


def status_info(text: str) -> str:
    """Info status line."""
    return f"[{INFO}]{text}[/{INFO}]"


def label(text: str) -> str:
    """Accent label for category headers."""
    return f"[bold {ACCENT}]{text}[/bold {ACCENT}]"


def cmd(text: str, color: str = SECONDARY) -> str:
    """Command name styling."""
    return f"[{color}]{text}[/{color}]"
