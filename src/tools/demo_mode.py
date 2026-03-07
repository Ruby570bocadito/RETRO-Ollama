import re
from typing import Dict, Optional, List
import hashlib

DEMO_MODE_ENABLED = False

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
MAC_PATTERN = re.compile(r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b')

def hash_value(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()[:8]

def censor_ip(ip: str) -> str:
    parts = ip.split('.')
    return f"{parts[0]}.XXX.XXX.{parts[3]}"

def censor_domain(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) > 2:
        return f"*.{parts[-2]}.{parts[-1]}"
    return f"*.{parts[-1]}"

def censor_email(email: str) -> str:
    parts = email.split('@')
    if len(parts) == 2:
        username = parts[0]
        masked = username[0] + "*" * (len(username) - 2) + username[-1] if len(username) > 2 else username[0] + "*"
        return f"{masked}@{parts[1]}"
    return email

def censor_mac(mac: str) -> str:
    parts = re.split(r'[:-]', mac)
    return f"{parts[0]}:{parts[1]}:XX:XX:XX:{parts[-1]}"

def enable_demo_mode():
    global DEMO_MODE_ENABLED
    DEMO_MODE_ENABLED = True

def disable_demo_mode():
    global DEMO_MODE_ENABLED
    DEMO_MODE_ENABLED = False

def is_demo_mode() -> bool:
    return DEMO_MODE_ENABLED

def censor_output(text: str) -> str:
    if not DEMO_MODE_ENABLED:
        return text
    
    text = IP_PATTERN.sub(lambda m: censor_ip(m.group()), text)
    text = DOMAIN_PATTERN.sub(lambda m: censor_domain(m.group()), text)
    text = EMAIL_PATTERN.sub(lambda m: censor_email(m.group()), text)
    text = MAC_PATTERN.sub(lambda m: censor_mac(m.group()), text)
    
    return text

def get_sensitive_patterns() -> List[str]:
    return [
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
    ]
