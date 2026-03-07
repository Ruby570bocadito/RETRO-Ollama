from typing import Dict, Optional
from src.tools.system import execute_command

STEALTH_LEVELS = {
    "light": {
        "name": "Light",
        "description": "Escaneo sigiloso básico",
        "nmap_args": "-sS -T2 -f",
        "delay": 0,
        "description_es": "Escaneo básico con fragmentación y velocidad reducida"
    },
    "moderate": {
        "name": "Moderate", 
        "description": "Evasión de IDS/Firewall básica",
        "nmap_args": "-sS -T1 -f -g 53 --script=firewall-bypass",
        "delay": 5,
        "description_es": "Evasión básica con cambios de puerto fuente"
    },
    "aggressive": {
        "name": "Aggressive",
        "description": "Evasión avanzada de IDS/IPS",
        "nmap_args": "-sS -T0 -f -g 53 --data-length 20 --ttl 128 --script=firewall-bypass,ids-evasion",
        "delay": 15,
        "description_es": "Técnicas avanzadas de evasión con payloads aleatorios"
    },
    "paranoid": {
        "name": "Paranoid",
        "description": "Evasión máxima - muy lento",
        "nmap_args": "-sS -T0 -f -f -p- -sI zombie --source-port 53 --data-length 50 --ttl 64 --randomize-hosts --script=banner,discover",
        "delay": 30,
        "description_es": "Evasión máxima con scan idle y fragmentación extrema"
    }
}

def stealth_scan(target: str, level: str = "light") -> Dict:
    if level not in STEALTH_LEVELS:
        level = "light"
    
    config = STEALTH_LEVELS[level]
    nmap_args = config["nmap_args"]
    
    return execute_command(f"nmap {nmap_args} {target}")


def stealth_scan_with_level(target: str, level: str = "light", ports: str = None) -> Dict:
    if level not in STEALTH_LEVELS:
        level = "light"
    
    config = STEALTH_LEVELS[level]
    nmap_args = config["nmap_args"]
    
    if ports:
        nmap_args += f" -p {ports}"
    else:
        nmap_args += " -p-"
    
    return execute_command(f"nmap {nmap_args} {target}")


def get_stealth_levels() -> Dict:
    return STEALTH_LEVELS


def get_stealth_level_info(level: str) -> Optional[Dict]:
    return STEALTH_LEVELS.get(level)
