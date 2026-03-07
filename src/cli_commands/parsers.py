import re
from typing import Optional, Dict, List
from typing import Optional


def extract_ip_or_domain(text: str) -> Optional[str]:
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    ip_match = re.search(ip_pattern, text)
    if ip_match:
        return ip_match.group()
    
    domain_match = re.search(domain_pattern, text)
    if domain_match:
        return domain_match.group()
    
    return None


def extract_ports(text: str) -> Optional[str]:
    port_pattern = r'-p\s*([\d,]+)|puertos?\s*([\d,]+)|port\s*([\d,]+)'
    match = re.search(port_pattern, text, re.IGNORECASE)
    if match:
        for g in match.groups():
            if g:
                return g
    
    single_port = r'\b(\d+)\b'
    if re.search(r'\b(puerto|port)\s+\d+\b', text, re.IGNORECASE):
        match = re.search(r'(puerto|port)\s+(\d+)', text, re.IGNORECASE)
        if match:
            return match.group(2)
    
    return None


def detect_intent(text: str) -> Dict:
    msg_lower = text.lower()
    intent = {
        "action": None,
        "target": extract_ip_or_domain(text),
        "ports": extract_ports(text),
        "tool": None,
        "params": {}
    }
    
    if any(w in msg_lower for w in ['escanea', 'scan', 'analiza', 'target', 'objetivo', 'mapea', 'haz un escaneo']):
        intent["action"] = "scan"
        
        if any(w in msg_lower for w in ['evasion', 'ids', 'ips', 'firewall', 'sigiloso', 'stealth', 'oculto', 'sin detected', 'indetectable']):
            intent["tool"] = "stealth"
        elif any(w in msg_lower for w in ['vuln', 'vulnerab', 'exploit', 'cve', 'vulnerabilidad']):
            intent["tool"] = "vuln"
        elif any(w in msg_lower for w in ['web', 'http', 'sitio', 'pagina', 'app', 'webapp']):
            intent["tool"] = "web"
        elif any(w in msg_lower for w in ['directorio', 'dir', 'carpeta', 'content', 'ruta']):
            intent["tool"] = "dir"
        elif any(w in msg_lower for w in ['completo', 'full', 'todo', 'profundo', 'all', 'exhaustivo']):
            intent["tool"] = "full"
        elif any(w in msg_lower for w in ['rápido', 'quick', 'basic', 'simple', 'veloz']):
            intent["tool"] = "quick"
        elif any(w in msg_lower for w in ['puerto', 'port', 'puertos especificos']):
            intent["tool"] = "custom"
        elif any(w in msg_lower for w in ['os', 'sistema operativo', 'detectar so']):
            intent["tool"] = "os"
        else:
            intent["tool"] = "quick"
    
    elif any(w in msg_lower for w in ['busca', 'search', 'exploit', 'cve', 'busca exploit', 'busca vulnerable']):
        intent["action"] = "search"
        if intent["target"]:
            intent["params"]["keyword"] = intent["target"]
        else:
            keywords = ['apache', 'nginx', 'wordpress', 'mysql', 'ssh', 'ftp', 'smb', 'redis', 'postgres', 'windows', 'linux']
            for kw in keywords:
                if kw in msg_lower:
                    intent["params"]["keyword"] = kw
                    break
    
    elif any(w in msg_lower for w in ['automático', 'autopwn', 'todo junto', 'pentest completo', 'full audit', 'todo automatico']):
        intent["action"] = "autopwn"
    
    elif any(w in msg_lower for w in ['ejecuta', 'run', 'corre', 'ejecutar', 'haz']):
        intent["action"] = "execute"
    
    elif any(w in msg_lower for w in ['genera', 'crea', 'make', 'build', 'script', 'código', 'payload', 'shell']):
        intent["action"] = "generate"
        if any(w in msg_lower for w in ['reverse', 'backdoor', 'bind']):
            intent["params"]["type"] = "shell"
        elif any(w in msg_lower for w in ['exploit', 'poc']):
            intent["params"]["type"] = "exploit"
        elif any(w in msg_lower for w in ['tool', 'herramienta', 'automation']):
            intent["params"]["type"] = "tool"
        else:
            intent["params"]["type"] = "script"
    
    elif any(w in msg_lower for w in ['reporte', 'report', 'documenta', 'informe']):
        intent["action"] = "report"
    
    elif any(w in msg_lower for w in ['archivos', 'files', 'scripts', 'generados', 'lista']):
        intent["action"] = "list_files"
    
    elif any(w in msg_lower for w in ['analiza', 'analisis', 'analyze', 'resultados']):
        intent["action"] = "analyze"
    
    elif any(w in msg_lower for w in ['fuerza bruta', 'brute', 'password', 'credencial']):
        intent["action"] = "bruteforce"
    
    return intent
