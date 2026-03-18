from typing import Dict, List, Optional
from datetime import datetime
import json

VULNERABILITY_DATABASE = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "severity": "critical",
        "cvss": 10.0,
        "description": "Remote code execution in Apache Log4j",
        "affected": ["log4j-core >= 2.0.0", "log4j-core <= 2.14.1"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "exploit_available": True
    },
    "CVE-2021-45046": {
        "name": "Log4j DoS",
        "severity": "high",
        "cvss": 9.8,
        "description": "Denial of service in Apache Log4j",
        "affected": ["log4j-core 2.0-beta9 to 2.15.0"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-45046"],
        "exploit_available": True
    },
    "CVE-2022-22965": {
        "name": "Spring4Shell",
        "severity": "critical",
        "cvss": 9.8,
        "description": "Remote code execution in Spring Framework",
        "affected": ["JDK 9+", "Spring Framework 5.3.0 to 5.3.17"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
        "exploit_available": True
    },
    "CVE-2023-44487": {
        "name": "HTTP/2 Rapid Reset",
        "severity": "high",
        "cvss": 7.5,
        "description": "HTTP/2 Rapid Reset Attack",
        "affected": ["Multiple HTTP/2 implementations"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
        "exploit_available": False
    },
    "CVE-2024-1709": {
        "name": "ConnectWise ScreenConnect Auth Bypass",
        "severity": "critical",
        "cvss": 10.0,
        "description": "Authentication bypass in ConnectWise ScreenConnect",
        "affected": ["ScreenConnect < 23.9.8"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1709"],
        "exploit_available": True
    },
    "CVE-2024-3400": {
        "name": "Palo Alto PAN-OS GlobalProtect",
        "severity": "critical",
        "cvss": 10.0,
        "description": "Command injection in PAN-OS GlobalProtect",
        "affected": ["PAN-OS 10.2", "PAN-OS 11.0", "PAN-OS 11.1"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3400"],
        "exploit_available": True
    }
}

COMMON_VULNERABILITIES = {
    "web": [
        {"name": "SQL Injection", "severity": "critical", "owasp": "A03:2021"},
        {"name": "Cross-Site Scripting (XSS)", "severity": "high", "owasp": "A03:2021"},
        {"name": "Broken Authentication", "severity": "high", "owasp": "A07:2021"},
        {"name": "Insecure Direct Object References", "severity": "medium", "owasp": "A01:2021"},
        {"name": "Security Misconfiguration", "severity": "medium", "owasp": "A05:2021"},
        {"name": "Sensitive Data Exposure", "severity": "high", "owasp": "A02:2021"},
        {"name": "Missing Function Level Access Control", "severity": "medium", "owasp": "A01:2021"},
        {"name": "CSRF", "severity": "medium", "owasp": "A04:2021"},
    ],
    "network": [
        {"name": "Default Credentials", "severity": "critical"},
        {"name": "Open Sensitive Ports", "severity": "high"},
        {"name": "Outdated SSL/TLS", "severity": "medium"},
        {"name": "SMB Signing Disabled", "severity": "high"},
        {"name": "Unencrypted FTP", "severity": "high"},
        {"name": "Telnet Enabled", "severity": "high"},
    ],
    "system": [
        {"name": "Outdated OS/Patches", "severity": "high"},
        {"name": "Weak Password Policy", "severity": "medium"},
        {"name": "Unnecessary Services Running", "severity": "medium"},
        {"name": "Firewall Disabled", "severity": "high"},
        {"name": "No Antivirus", "severity": "critical"},
    ]
}


class VulnerabilityDatabase:
    def __init__(self):
        self.custom_vulns = {}
    
    def get_cve(self, cve_id: str) -> Optional[Dict]:
        cve_id = cve_id.upper()
        if cve_id in VULNERABILITY_DATABASE:
            return VULNERABILITY_DATABASE[cve_id]
        return self.custom_vulns.get(cve_id)
    
    def search_cve(self, keyword: str) -> List[Dict]:
        keyword = keyword.lower()
        results = []
        
        for cve_id, data in VULNERABILITY_DATABASE.items():
            if keyword in data["name"].lower() or keyword in cve_id.lower():
                results.append({"cve": cve_id, **data})
        
        return results
    
    def get_by_severity(self, severity: str) -> List[Dict]:
        severity = severity.lower()
        results = []
        for cve_id, data in VULNERABILITY_DATABASE.items():
            if data["severity"].lower() == severity:
                results.append({"cve": cve_id, **data})
        return results
    
    def get_exploitable(self) -> List[Dict]:
        results = []
        for cve_id, data in VULNERABILITY_DATABASE.items():
            if data.get("exploit_available"):
                results.append({"cve": cve_id, **data})
        return results
    
    def add_custom_cve(self, cve_id: str, data: Dict):
        self.custom_vulns[cve_id.upper()] = data
    
    def get_common_vulns(self, category: str) -> List[Dict]:
        return COMMON_VULNERABILITIES.get(category, [])
    
    def get_all_categories(self) -> List[str]:
        return list(COMMON_VULNERABILITIES.keys())
    
    def suggest_remediation(self, vuln_name: str) -> str:
        remediation_map = {
            "sql injection": "Use parameterized queries, prepared statements, ORMs",
            "xss": "Implement output encoding, Content Security Policy",
            "default credentials": "Change all default passwords immediately",
            "outdated": "Apply latest security patches",
            "weak password": "Implement strong password policy, MFA",
            "open sensitive ports": "Close unnecessary ports, configure firewall"
        }
        
        vuln_lower = vuln_name.lower()
        for key, remediation in remediation_map.items():
            if key in vuln_lower:
                return remediation
        return "Review and apply security best practices"


def get_vulnerability_info(cve_id: str) -> Optional[Dict]:
    db = VulnerabilityDatabase()
    return db.get_cve(cve_id)


def search_vulnerabilities(keyword: str) -> List[Dict]:
    db = VulnerabilityDatabase()
    return db.search_cve(keyword)


def get_severity_summary() -> Dict:
    db = VulnerabilityDatabase()
    return {
        "critical": len(db.get_by_severity("critical")),
        "high": len(db.get_by_severity("high")),
        "medium": len(db.get_by_severity("medium")),
        "low": len(db.get_by_severity("low"))
    }
