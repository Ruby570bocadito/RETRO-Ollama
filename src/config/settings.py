import os
from pathlib import Path
from typing import Dict, List

BASE_DIR = Path(__file__).parent.parent
CONFIG_FILE = BASE_DIR / "config.yaml"
HISTORY_FILE = BASE_DIR / "history.json"
REPORTS_DIR = BASE_DIR / "reports"
SCANS_DIR = BASE_DIR / "scans"

OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
LMSTUDIO_HOST: str = os.getenv("LMSTUDIO_HOST", "http://localhost:1234/v1")
DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "llama3.2")
DEFAULT_BACKEND: str = os.getenv("DEFAULT_BACKEND", "ollama")

# =============================================================================
# CONFIGURACIÓN DE API KEYS
# =============================================================================
# Establece las variables de entorno para habilitar servicios OSINT:
#
# - SHODAN_API_KEY:      https://www.shodan.io/api
# - VIRUSTOTAL_API_KEY:  https://www.virustotal.com/gui/join-free
# - HUNTER_API_KEY:      https://hunter.io/api
# - CENSYS_API_KEY:      https://censys.io/api
# - SECURITYTRAILS_API_KEY: https://securitytrails.com/
#
# Ejemplo (Linux/Mac):
#   export SHODAN_API_KEY="tu_api_key_aqui"
#   export VIRUSTOTAL_API_KEY="tu_api_key_aqui"
#   export HUNTER_API_KEY="tu_api_key_aqui"
#   export CENSYS_API_KEY="tu_api_key_aqui"
#   export SECURITYTRAILS_API_KEY="tu_api_key_aqui"
#
# Ejemplo (Windows):
#   set SHODAN_API_KEY=tu_api_key_aqui
#   set VIRUSTOTAL_API_KEY=tu_api_key_aqui
#   set HUNTER_API_KEY=tu_api_key_aqui
#   set CENSYS_API_KEY=tu_api_key_aqui
#   set SECURITYTRAILS_API_KEY=tu_api_key_aqui
#
# O ejecuta: python main.py --setup-keys
# =============================================================================

SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
HUNTER_API_KEY: str = os.getenv("HUNTER_API_KEY", "")
CENSYS_API_KEY: str = os.getenv("CENSYS_API_KEY", "")
SECURITYTRAILS_API_KEY: str = os.getenv("SECURITYTRAILS_API_KEY", "")

TOOLS_CATEGORIES: Dict[str, List[str]] = {
    "recon": ["nmap", "whatweb", "theHarvester", "dnsenum", "wappalyzer"],
    "scanning": ["nikto", "nmap-scripts", "sqlmap", "dirb", "gobuster", "commix"],
    "exploitation": ["msfconsole", "searchsploit", "hydra", "john", "msfvenom"],
    "post": ["meterpreter", "reverse-shell", "pivoting"]
}

COLORS: Dict[str, str] = {
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


def check_api_keys() -> Dict[str, bool]:
    """Verifica qué API keys están configuradas"""
    return {
        "shodan": bool(SHODAN_API_KEY),
        "virustotal": bool(VIRUSTOTAL_API_KEY),
        "hunter": bool(HUNTER_API_KEY)
    }


def get_missing_keys() -> List[str]:
    """Retorna lista de API keys faltantes"""
    missing: List[str] = []
    if not SHODAN_API_KEY:
        missing.append("SHODAN_API_KEY")
    if not VIRUSTOTAL_API_KEY:
        missing.append("VIRUSTOTAL_API_KEY")
    if not HUNTER_API_KEY:
        missing.append("HUNTER_API_KEY")
    return missing
