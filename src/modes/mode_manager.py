import json
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
MODE_FILE = BASE_DIR / "mode.json"

MODES = {
    "pentester": {
        "name": "Pentester",
        "color": "#FF6B35",
        "description": "Modo ataque - Vulnerabilidades, exploits, pentesting",
        "icon": "⚔️"
    },
    "blue": {
        "name": "Blue Team",
        "color": "#00A8E8",
        "description": "Modo defensa - Seguridad, malware, hardening",
        "icon": "🛡️"
    },
    "osint": {
        "name": "OSINT",
        "color": "#00FF88",
        "description": "Investigación - Whois, subdomains, Shodan",
        "icon": "🔍"
    },
    "forense": {
        "name": "Forense",
        "color": "#9B59B6",
        "description": "Análisis forense - Evidencias, disk, memory",
        "icon": "🔎"
    },
    "bugbounty": {
        "name": "Bug Bounty",
        "color": "#F1C40F",
        "description": "Bug hunting - Recon, vuln hunting, reporting",
        "icon": "🎯"
    }
}

DEFAULT_MODE = "pentester"


def get_current_mode() -> str:
    try:
        if MODE_FILE.exists():
            with open(MODE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                mode = data.get("mode", DEFAULT_MODE)
                if mode in MODES:
                    return mode
    except:
        pass
    return DEFAULT_MODE


def set_mode(mode: str) -> bool:
    if mode not in MODES:
        return False
    
    try:
        with open(MODE_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "mode": mode,
                "timestamp": datetime.now().isoformat()
            }, f, ensure_ascii=False, indent=2)
        return True
    except:
        return False


def get_mode_info(mode: str) -> Optional[Dict]:
    return MODES.get(mode)


def list_modes() -> Dict:
    return MODES


def get_all_modes_list() -> list:
    return list(MODES.keys())
