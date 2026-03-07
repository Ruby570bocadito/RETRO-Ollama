import re
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, List, Dict

BASE_DIR = Path(__file__).parent.parent.parent
AUDIT_LOG = BASE_DIR / "audit.log"

RESTRICTED_PATTERNS = {
    'malware': ['malware', 'virus', 'ransomware', 'trojan', 'spyware', 'worm', 'adware'],
    'espionage': ['keylog', 'keylogger', 'capture keystrokes', 'record keystrokes', ' keystroke'],
    'unauthorized': ['backdoor', 'remote access trojan', 'rat', 'botnet', 'ddos', 'bot'],
    'destructive': ['destroy', 'wipe', 'format', 'delete all', 'brick'],
    'bypass': ['bypass antivirus', 'bypass av', 'fud', 'undetectable'],
    'exfiltration': ['exfiltrate', 'data breach', 'steal data', 'credential harvest'],
    'unauthorized_access': ['bypass authentication', 'bypass login', 'crack password'],
}

WARNING_PATTERNS = {
    'offensive': ['reverse shell', 'bind shell', 'meterpreter', 'webshell', 'shellcode', 'exploit'],
    'network': ['port scan', 'network scan', 'brute force', 'password crack'],
    'web': ['sql injection', 'xss', 'csrf', 'web vulnerability', 'directory traversal'],
    'social': ['phishing', 'social engineering', 'spear phish'],
}

def sanitize_target(target: str) -> Optional[str]:
    if not target:
        return None
    
    target = target.strip()
    
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    
    if re.match(ip_pattern, target) and all(0 <= int(x) <= 255 for x in target.split('.')):
        return target
    
    if re.match(domain_pattern, target) or re.match(hostname_pattern, target):
        return target
    
    if re.match(url_pattern, target):
        return target
    
    if re.match(r'^\d+$', target):
        return target
    
    return None

def validate_command(command: str) -> Tuple[bool, Optional[str]]:
    dangerous_chars = ['&&', '||', ';', '|', '`', '$(', '${', '\\n', '\\r', '>', '<', '>>']
    
    for char in dangerous_chars:
        if char in command:
            return False, f"Dangerous character detected: {char}"
    
    return True, None

SECURITY_FILTER_ENABLED = False

def analyze_request(prompt: str) -> Tuple[str, str]:
    if not SECURITY_FILTER_ENABLED:
        return "ALLOWED", "filter_disabled"
    
    prompt_lower = prompt.lower()
    
    for category, terms in RESTRICTED_PATTERNS.items():
        for term in terms:
            if term in prompt_lower:
                return "BLOCKED", category
    
    warnings = []
    for category, terms in WARNING_PATTERNS.items():
        for term in terms:
            if term in prompt_lower:
                warnings.append(category)
    
    if warnings:
        return "WARNING", ",".join(warnings)
    
    return "ALLOWED", ""

def check_and_log(prompt: str, model: str = "unknown") -> Tuple[bool, str]:
    status, category = analyze_request(prompt)
    
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "prompt": prompt[:200],
        "model": model,
        "status": status,
        "category": category
    }
    
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except:
        pass
    
    return status != "BLOCKED", status

def get_audit_log(limit: int = 50) -> List[Dict]:
    if not AUDIT_LOG.exists():
        return []
    
    try:
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
            logs = [json.loads(line) for line in lines[-limit:] if line.strip()]
            return list(reversed(logs))
    except:
        return []

def get_blocked_count() -> int:
    if not AUDIT_LOG.exists():
        return 0
    
    try:
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            count = sum(1 for line in f if '"BLOCKED"' in line)
            return count
    except:
        return 0
