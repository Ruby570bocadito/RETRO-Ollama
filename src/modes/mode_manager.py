import json
import logging
from pathlib import Path
from typing import Dict, Optional

from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent.parent
MODE_FILE = BASE_DIR / "mode.json"

MODES = {
    "autonomous": {
        "name": "Autonomous",
        "color": "#808080",
        "description": "Agente autonomo - Pensamiento, ejecucion automatica",
        "icon": "[A]"
    },
    "pentester": {
        "name": "Pentester",
        "color": "#FF6B35",
        "description": "Modo ataque - Vulnerabilidades, exploits, pentesting",
        "icon": "[P]"
    },
    "blue": {
        "name": "Blue Team",
        "color": "#00A8E8",
        "description": "Modo defensa - Seguridad, malware, hardening",
        "icon": "[B]"
    },
    "osint": {
        "name": "OSINT",
        "color": "#00FF88",
        "description": "Investigacion - Whois, subdomains, Shodan",
        "icon": "[O]"
    },
    "forense": {
        "name": "Forense",
        "color": "#9B59B6",
        "description": "Analisis forense - Evidencias, disk, memory",
        "icon": "[F]"
    },
    "bugbounty": {
        "name": "Bug Bounty",
        "color": "#F1C40F",
        "description": "Bug hunting - Recon, vuln hunting, reporting",
        "icon": "[BB]"
    },
    "redteam": {
        "name": "Red Team",
        "color": "#E74C3C",
        "description": "Simulacion de adversario - APT, movimiento lateral",
        "icon": "[RT]"
    },
    "vulnassessment": {
        "name": "Vuln Assessment",
        "color": "#3498DB",
        "description": "Evaluacion de vulnerabilidades - CVSS, remediacion",
        "icon": "[VA]"
    },
    "network": {
        "name": "Network",
        "color": "#2ECC71",
        "description": "Seguridad de redes - Firewalls, segmentacion",
        "icon": "[N]"
    },
    "webapp": {
        "name": "Web App",
        "color": "#9B59B6",
        "description": "Pentesting web - OWASP Top 10, inyecciones",
        "icon": "[W]"
    },
    "social": {
        "name": "Social Engineering",
        "color": "#E67E22",
        "description": "Ingenieria social - Phishing, vishing, awareness",
        "icon": "[SE]"
    },
    "devsecops": {
        "name": "DevSecOps",
        "color": "#00CED1",
        "description": "CI/CD security - SAST, DAST, container security",
        "icon": "[DS]"
    },
    "malware": {
        "name": "Malware Analysis",
        "color": "#DC143C",
        "description": "Analisis de malware - Sandbox, reverse engineering",
        "icon": "[M]"
    },
    "iot": {
        "name": "IoT Security",
        "color": "#FF8C00",
        "description": "Seguridad IoT - Protocolos Zigbee, MQTT, CoAP",
        "icon": "[IoT]"
    },
    "cloud": {
        "name": "Cloud Security",
        "color": "#4169E1",
        "description": "AWS, Azure, GCP - Misconfigs, cloud Pentest",
        "icon": "[C]"
    },
    "mobile": {
        "name": "Mobile Security",
        "color": "#32CD32",
        "description": "Android/iOS - APK analysis, jailbreak detection",
        "icon": "[Mob]"
    },
    "compliance": {
        "name": "Compliance",
        "color": "#FFD700",
        "description": "HIPAA, PCI-DSS, ISO27001 - Auditorias",
        "icon": "[Comp]"
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
                logger.warning(f"Invalid mode '{mode}' in mode.json, using default")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in mode.json: {e}")
    except IOError as e:
        logger.error(f"Error reading mode.json: {e}")
    except Exception as e:
        logger.error(f"Unexpected error reading mode: {e}")
    return DEFAULT_MODE


def set_mode(mode: str) -> bool:
    if mode not in MODES:
        logger.warning(f"Attempted to set invalid mode: {mode}")
        return False
    
    try:
        with open(MODE_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "mode": mode,
                "timestamp": datetime.now().isoformat()
            }, f, ensure_ascii=False, indent=2)
        logger.info(f"Mode changed to: {mode}")
        return True
    except IOError as e:
        logger.error(f"Error writing mode.json: {e}")
    except Exception as e:
        logger.error(f"Unexpected error setting mode: {e}")
    return False


def get_mode_info(mode: str) -> Optional[Dict]:
    return MODES.get(mode)


def list_modes() -> Dict:
    return MODES


def get_all_modes_list() -> list:
    return list(MODES.keys())
