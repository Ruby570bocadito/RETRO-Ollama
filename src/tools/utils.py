import hashlib
import base64
import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import ipaddress


def is_valid_ip(ip: str) -> bool:
    """Valida si es una IP válida"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Verifica si es IP privada"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Valida formato de dominio"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def extract_urls(text: str) -> List[str]:
    """Extrae URLs de un texto"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)


def extract_emails(text: str) -> List[str]:
    """Extrae emails de un texto"""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(email_pattern, text)


def extract_ips(text: str) -> List[str]:
    """Extrae IPs de un texto"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, text)


def calculate_hash(data: str, algorithm: str = "sha256") -> str:
    """Calcula hash de una cadena"""
    if algorithm == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data.encode()).hexdigest()
    return ""


def encode_base64(data: str) -> str:
    """Codifica en base64"""
    return base64.b64encode(data.encode()).decode()


def decode_base64(data: str) -> str:
    """Decodifica base64"""
    try:
        return base64.b64decode(data.encode()).decode()
    except Exception:
        return ""


def parse_nmap_output(output: str) -> Dict[str, Any]:
    """Parsea salida de nmap"""
    result = {
        "open_ports": [],
        "closed_ports": [],
        "services": {},
        "os_guess": None,
        "scripts": {}
    }
    
    port_pattern = r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)'
    for match in re.finditer(port_pattern, output):
        port, proto, state, service, version = match.groups()
        if state == "open":
            result["open_ports"].append({
                "port": int(port),
                "protocol": proto,
                "service": service,
                "version": version.strip()
            })
            result["services"][service] = version.strip()
    
    os_match = re.search(r'OS details: (.+)', output)
    if os_match:
        result["os_guess"] = os_match.group(1)
    
    return result


def parse_nikto_output(output: str) -> List[Dict]:
    """Parsea salida de nikto"""
    findings = []
    for line in output.split('\n'):
        if "+ " in line and ("vulnerability" in line.lower() or "issue" in line.lower()):
            findings.append({
                "finding": line.strip(),
                "severity": "medium"
            })
    return findings


def severity_to_cvss(severity: str) -> float:
    """Convierte severidad textual a CVSS aproximado"""
    mapping = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 3.5,
        "info": 0.0
    }
    return mapping.get(severity.lower(), 5.0)


def cvss_to_severity(cvss: float) -> str:
    """Convierte CVSS a severidad"""
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    elif cvss > 0:
        return "Low"
    return "Info"


def format_timestamp(timestamp: str = None) -> str:
    """Formatea timestamp"""
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize_filename(filename: str) -> str:
    """Limpia nombre de archivo"""
    return re.sub(r'[^\w\-.]', '_', filename)[:255]


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Trunca string"""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def merge_dicts(*dicts: Dict) -> Dict:
    """Merge múltiples diccionarios"""
    result = {}
    for d in dicts:
        result.update(d)
    return result


def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Divide lista en chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def get_severity_color(severity: str) -> str:
    """Retorna color para severidad"""
    colors = {
        "critical": "#FF4757",
        "high": "#FF6B35",
        "medium": "#FFD93D",
        "low": "#00FF88",
        "info": "#A0A0A0"
    }
    return colors.get(severity.lower(), "#A0A0A0")


def parse_json_safe(json_str: str) -> Optional[Dict]:
    """Parsea JSON de forma segura"""
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return None


def clean_html(text: str) -> str:
    """Limpia HTML de un texto"""
    clean = re.sub(r'<[^>]+>', '', text)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()


def count_findings_by_severity(findings: List[Dict]) -> Dict[str, int]:
    """Cuenta hallazgos por severidad"""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts
