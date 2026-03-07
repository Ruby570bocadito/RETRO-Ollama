import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
CONFIG_FILE = BASE_DIR / "config.yaml"
HISTORY_FILE = BASE_DIR / "history.json"
REPORTS_DIR = BASE_DIR / "reports"
SCANS_DIR = BASE_DIR / "scans"

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "llama3.2")

TOOLS_CATEGORIES = {
    "recon": ["nmap", "whatweb", "theHarvester", "dnsenum", "wappalyzer"],
    "scanning": ["nikto", "nmap-scripts", "sqlmap", "dirb", "gobuster", "commix"],
    "exploitation": ["msfconsole", "searchsploit", "hydra", "john", "msfvenom"],
    "post": ["meterpreter", "reverse-shell", "pivoting"]
}

COLORS = {
    "primary": "#FF6B35",
    "secondary": "#1A1A2E",
    "accent": "#00FF88",
    "warning": "#FFD93D",
    "error": "#FF4757",
    "text": "#FFFFFF",
    "text_secondary": "#A0A0A0"
}

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(SCANS_DIR, exist_ok=True)
