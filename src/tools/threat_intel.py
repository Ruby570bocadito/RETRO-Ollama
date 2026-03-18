from typing import Dict, List, Optional
from datetime import datetime
import re

THREAT_CATEGORIES = {
    "malware": {
        "ransomware": ["lockbit", "conti", "revil", "REvil", "WannaCry", "Petya", "Ryuk"],
        "trojan": ["emotet", "trickbot", "qakbot", "icedid", "cobalt strike"],
        "backdoor": ["cobalt", "metasploit", "pupy", "koadic"],
        "spyware": ["spyware", "keylogger", "stalkerware"]
    },
    "attack_patterns": {
        "phishing": ["phishing", "spear phishing", "whaling", "vishing", "smishing"],
        "brute_force": ["brute force", "credential stuffing", "password spray"],
        "exploitation": ["sql injection", "xss", "rce", "buffer overflow"],
        "privilege_escalation": ["privilege escalation", "privesc", "rootkit"]
    },
    "threat_actors": {
        "apt": ["apt29", "apt28", "apt41", "lazarus", "方程式", "cozy bear", "fancy bear"],
        "cybercrime": ["lapsus$", "clop", "dark side", "blackmatter"],
        "hacktivist": ["anonymous", "killnet"]
    }
}

IOC_PATTERNS = {
    "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "ipv6": r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
    "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "url": r'https?://[^\s]+',
    "cve": r'CVE-\d{4}-\d{4,}',
    "file_path": r'(?:[A-Za-z]:\\|/)(?:[^\\/:*?"<>|\r\n]+[/\\])*[^\\/:*?"<>|\r\n]*',
    "registry": r'HKEY_(?:LOCAL_MACHINE|USERS|CURRENT_USER)',
    "mutex": r'Global\\[^\\]+'
}

MALICIOUS_EXTENSIONS = [
    ".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".vbs",
    ".scr", ".pif", ".application", ".gadget", ".msi", ".msp",
    ".com", ".jar", ".class", ".apk", ".xll", ".reg", ".hlp"
]

SUSPICIOUS_EXTENSIONS = [
    ".vbs", ".ps1", ".bat", ".cmd", ".js", ".jse", ".vbe", ".wsf",
    ".wsh", ".scr", ".pif", ".application", ".gadget"
]

SUSPICIOUS_PROCESSES = [
    "mimikatz", "pwdump", "procdump", "lsass", "lsassy", "sekurlsa",
    "mimikatz", "kerberoast", "gcrack", "rubeus", "mimikatz",
    "psexec", "wce", "gsecdump", "cachedump", "lsalist"
]


class ThreatIntelligence:
    def __init__(self):
        self.iocs = []
        self.threats = []
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extrae todos los IOCs de un texto"""
        results = {}
        
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            results[ioc_type] = list(set(matches))
        
        return results
    
    def check_ip_reputation(self, ip: str) -> Dict:
        """Verifica reputación de IP"""
        result = {
            "ip": ip,
            "reputation": "unknown",
            "tags": [],
            "last_seen": None,
            "confidence": 0
        }
        
        private_ranges = ["10.", "172.16.", "192.168.", "127."]
        if any(ip.startswith(r) for r in private_ranges):
            result["reputation"] = "private"
            result["tags"].append("private-ip")
            return result
        
        common_dns = ["google", "cloudflare", "amazon", "microsoft", "apple"]
        result["reputation"] = "benign"
        result["tags"].append("cloud-provider")
        result["confidence"] = 50
        
        return result
    
    def check_hash_reputation(self, hash_value: str) -> Dict:
        """Verifica reputación de hash"""
        result = {
            "hash": hash_value,
            "malware_family": None,
            "reputation": "unknown",
            "first_seen": None,
            "detection_ratio": None
        }
        
        if len(hash_value) == 32:
            result["hash_type"] = "MD5"
        elif len(hash_value) == 40:
            result["hash_type"] = "SHA1"
        elif len(hash_value) == 64:
            result["hash_type"] = "SHA256"
        
        return result
    
    def check_domain_reputation(self, domain: str) -> Dict:
        """Verifica reputación de dominio"""
        result = {
            "domain": domain,
            "reputation": "unknown",
            "categories": [],
            "registrar": None,
            "creation_date": None
        }
        
        tld = domain.split('.')[-1].lower()
        if tld in ["tk", "ml", "ga", "cf", "gq", "xyz", "top"]:
            result["reputation"] = "suspicious"
            result["categories"].append("free-tld")
        
        suspicious_words = ["free", "download", "crack", "hack", "keygen"]
        if any(w in domain.lower() for w in suspicious_words):
            result["reputation"] = "suspicious"
            result["categories"].append("suspicious-keyword")
        
        return result
    
    def classify_threat(self, text: str) -> List[Dict]:
        """Clasifica amenazas en texto"""
        threats = []
        text_lower = text.lower()
        
        for category, families in THREAT_CATEGORIES["malware"].items():
            for family in families:
                if family.lower() in text_lower:
                    threats.append({
                        "type": "malware",
                        "family": family,
                        "category": category,
                        "confidence": "high"
                    })
        
        for category, patterns in THREAT_CATEGORIES["attack_patterns"].items():
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    threats.append({
                        "type": "attack_pattern",
                        "pattern": pattern,
                        "category": category,
                        "confidence": "medium"
                    })
        
        return threats
    
    def analyze_file_indicators(self, filename: str, filepath: str = None) -> Dict:
        """Analiza indicadores de archivo"""
        result = {
            "filename": filename,
            "suspicious": False,
            "reasons": [],
            "risk_level": "low"
        }
        
        ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
        
        if ext in MALICIOUS_EXTENSIONS:
            result["suspicious"] = True
            result["reasons"].append(f"Potentially malicious extension: {ext}")
            result["risk_level"] = "high"
        
        if ext in SUSPICIOUS_EXTENSIONS:
            result["suspicious"] = True
            result["reasons"].append(f"Suspicious extension: {ext}")
            if result["risk_level"] != "high":
                result["risk_level"] = "medium"
        
        suspicious_patterns = ["hidden", "tmp", "temp", "appdata", "localappdata"]
        if filepath and any(p in filepath.lower() for p in suspicious_patterns):
            result["suspicious"] = True
            result["reasons"].append("File in suspicious location")
        
        return result
    
    def check_process_safety(self, process_name: str) -> Dict:
        """Verifica si un proceso es malicioso"""
        result = {
            "process": process_name,
            "is_malicious": False,
            "category": "unknown",
            "description": None
        }
        
        process_lower = process_name.lower()
        
        for category, processes in THREAT_CATEGORIES["malware"].items():
            for proc in processes:
                if proc in process_lower:
                    result["is_malicious"] = True
                    result["category"] = category
                    result["description"] = f"Known {category} tool"
                    return result
        
        if process_lower in [p.lower() for p in SUSPICIOUS_PROCESSES]:
            result["is_malicious"] = True
            result["category"] = "credential-theft"
            result["description"] = "Suspicious process - possible credential theft"
        
        return result
    
    def generate_threat_report(self, iocs: Dict, threats: List[Dict]) -> str:
        """Genera reporte de amenazas"""
        report = "# Threat Intelligence Report\n\n"
        report += f"**Generated:** {datetime.now().isoformat()}\n\n"
        
        if iocs.get("ipv4"):
            report += "## Indicators (IPs)\n"
            for ip in iocs["ipv4"]:
                report += f"- {ip}\n"
            report += "\n"
        
        if iocs.get("domain"):
            report += "## Indicators (Domains)\n"
            for domain in iocs["domain"]:
                report += f"- {domain}\n"
            report += "\n"
        
        if iocs.get("sha256"):
            report += "## Indicators (Hashes)\n"
            for h in iocs["sha256"]:
                report += f"- {h}\n"
            report += "\n"
        
        if threats:
            report += "## Threat Classification\n"
            for threat in threats:
                report += f"- **{threat['type']}**: {threat.get('family', threat.get('pattern', 'N/A'))}\n"
            report += "\n"
        
        return report


def quick_ioc_check(text: str) -> Dict:
    """Función rápida de verificación de IOCs"""
    ti = ThreatIntelligence()
    iocs = ti.extract_iocs(text)
    threats = ti.classify_threat(text)
    
    return {
        "iocs": iocs,
        "threats": threats,
        "total_iocs": sum(len(v) for v in iocs.values()),
        "threat_count": len(threats)
    }
