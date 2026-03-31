from typing import Dict, List, Optional
import re
from datetime import datetime

COMPLIANCE_CHECKS = {
    "cis_benchmarks": {
        "linux": [
            {"id": "CIS-1.1.1", "title": "Ensure mounting of cramfs filesystems is disabled", "severity": "high"},
            {"id": "CIS-1.1.2", "title": "Ensure mounting of squashfs filesystems is disabled", "severity": "high"},
            {"id": "CIS-1.1.3", "title": "Ensure mounting of udf filesystems is disabled", "severity": "medium"},
            {"id": "CIS-2.1.1", "title": "Ensure xinetd is not installed", "severity": "high"},
            {"id": "CIS-3.1.1", "title": "Ensure IP forwarding is disabled", "severity": "medium"},
            {"id": "CIS-3.2.1", "title": "Ensure packet redirect sending is disabled", "severity": "medium"},
            {"id": "CIS-3.3.1", "title": "Ensure source packet routing is disabled", "severity": "high"},
            {"id": "CIS-4.1.1", "title": "Ensure ICMP redirects are not accepted", "severity": "medium"},
            {"id": "CIS-4.2.1", "title": "Ensure SSH Protocol is 2", "severity": "high"},
            {"id": "CIS-5.1.1", "title": "Ensure permissions on /etc/passwd are configured", "severity": "high"},
            {"id": "CIS-5.1.2", "title": "Ensure permissions on /etc/shadow are configured", "severity": "high"},
            {"id": "CIS-5.2.1", "title": "Ensure SSH root login is disabled", "severity": "critical"},
            {"id": "CIS-5.2.2", "title": "Ensure SSH password authentication is disabled", "severity": "high"},
            {"id": "CIS-5.3.1", "title": "Ensure password complexity is configured", "severity": "medium"},
            {"id": "CIS-5.4.1.1", "title": "Ensure minimum password length is 15", "severity": "high"},
        ],
        "windows": [
            {"id": "CIS-1.1", "title": "Ensure password history is configured", "severity": "high"},
            {"id": "CIS-1.2", "title": "Ensure maximum password age is configured", "severity": "medium"},
            {"id": "CIS-1.3", "title": "Ensure minimum password age is configured", "severity": "medium"},
            {"id": "CIS-1.4", "title": "Ensure minimum password length is configured", "severity": "high"},
            {"id": "CIS-2.1.1", "title": "Ensure accounts administrator is renamed", "severity": "medium"},
            {"id": "CIS-2.3.1.1", "title": "Ensure Windows Defender is enabled", "severity": "critical"},
            {"id": "CIS-3.1.1", "title": "Ensure Windows Firewall is enabled", "severity": "critical"},
            {"id": "CIS-9.1.1", "title": "Ensure audit credentials validation is configured", "severity": "medium"},
        ]
    },
    
    "owasp": {
        "headers": [
            {"id": "OWASP-H-1", "title": "Security Header: Strict-Transport-Security", "severity": "high"},
            {"id": "OWASP-H-2", "title": "Security Header: X-Content-Type-Options", "severity": "medium"},
            {"id": "OWASP-H-3", "title": "Security Header: X-Frame-Options", "severity": "medium"},
            {"id": "OWASP-H-4", "title": "Security Header: Content-Security-Policy", "severity": "high"},
            {"id": "OWASP-H-5", "title": "Security Header: X-XSS-Protection", "severity": "low"},
            {"id": "OWASP-H-6", "title": "Security Header: Referrer-Policy", "severity": "low"},
            {"id": "OWASP-H-7", "title": "Security Header: Permissions-Policy", "severity": "low"},
        ],
        "config": [
            {"id": "OWASP-C-1", "title": "Debug mode disabled in production", "severity": "critical"},
            {"id": "OWASP-C-2", "title": "Error handling does not leak sensitive info", "severity": "high"},
            {"id": "OWASP-C-3", "title": "Sensitive data encrypted at rest", "severity": "critical"},
            {"id": "OWASP-C-4", "title": "HTTPS enforced", "severity": "high"},
            {"id": "OWASP-C-5", "title": "Secure cookies configured", "severity": "medium"},
        ]
    },
    
    "pci_dss": {
        "requirements": [
            {"id": "PCI-1.1", "title": "Firewall configuration maintained", "severity": "critical"},
            {"id": "PCI-2.1", "title": "Vendor-supplied defaults changed", "severity": "critical"},
            {"id": "PCI-3.1", "title": "Cardholder data protected", "severity": "critical"},
            {"id": "PCI-4.1", "title": "Transmission encryption", "severity": "critical"},
            {"id": "PCI-5.1", "title": "Anti-virus software used", "severity": "high"},
            {"id": "PCI-6.1", "title": "Secure systems developed", "severity": "critical"},
            {"id": "PCI-7.1", "title": "Access restricted by business need", "severity": "high"},
            {"id": "PCI-8.1", "title": "Unique IDs for access", "severity": "high"},
            {"id": "PCI-10.1", "title": "Audit logging implemented", "severity": "high"},
            {"id": "PCI-12.1", "title": "Security policy maintained", "severity": "medium"},
        ]
    },
    
    "nist": {
        "controls": [
            {"id": "NIST-AC-1", "title": "Access Control Policy", "severity": "high"},
            {"id": "NIST-AC-2", "title": "Account Management", "severity": "high"},
            {"id": "NIST-AC-3", "title": "Access Enforcement", "severity": "critical"},
            {"id": "NIST-AU-1", "title": "Audit Policy", "severity": "high"},
            {"id": "NIST-AU-2", "title": "Audit Events", "severity": "high"},
            {"id": "NIST-AU-3", "title": "Audit Content", "severity": "medium"},
            {"id": "NIST-SC-1", "title": "System Protection", "severity": "high"},
            {"id": "NIST-SC-7", "title": "Boundary Protection", "severity": "critical"},
            {"id": "NIST-SI-1", "title": "Flaw Remediation", "severity": "high"},
            {"id": "NIST-SI-2", "title": "Flaw Detection", "severity": "high"},
        ]
    }
}


class ComplianceChecker:
    def __init__(self, framework: str = "owasp"):
        self.framework = framework
        self.checks = COMPLIANCE_CHECKS.get(framework, {})
    
    def check_linux_system(self, system_info: Dict) -> List[Dict]:
        """Verifica compliance de sistema Linux"""
        results = []
        
        linux_checks = self.checks.get("linux", [])
        for check in linux_checks:
            result = {
                "id": check["id"],
                "title": check["title"],
                "severity": check["severity"],
                "status": "unknown",
                "evidence": ""
            }
            
            if check["id"] == "CIS-5.2.1":
                ssh_config = system_info.get("ssh_config", {})
                if ssh_config.get("permit_root_login") == "no":
                    result["status"] = "pass"
                else:
                    result["status"] = "fail"
                    result["evidence"] = "Root login allowed"
            
            results.append(result)
        
        return results
    
    def check_web_headers(self, headers: Dict) -> List[Dict]:
        """Verifica headers de seguridad web"""
        results = []
        
        header_checks = self.checks.get("headers", [])
        for check in header_checks:
            result = {
                "id": check["id"],
                "title": check["title"],
                "severity": check["severity"],
                "status": "unknown"
            }
            
            if check["id"] == "OWASP-H-1":
                if "Strict-Transport-Security" in headers:
                    result["status"] = "pass"
                else:
                    result["status"] = "fail"
            elif check["id"] == "OWASP-H-2":
                if headers.get("X-Content-Type-Options") == "nosniff":
                    result["status"] = "pass"
                else:
                    result["status"] = "fail"
            elif check["id"] == "OWASP-H-3":
                if headers.get("X-Frame-Options"):
                    result["status"] = "pass"
                else:
                    result["status"] = "fail"
            
            results.append(result)
        
        return results
    
    def calculate_compliance_score(self, results: List[Dict]) -> Dict:
        """Calcula puntuación de compliance"""
        total = len(results)
        if total == 0:
            return {"score": 0, "level": "N/A"}
        
        passed = len([r for r in results if r.get("status") == "pass"])
        failed = len([r for r in results if r.get("status") == "fail"])
        
        score = (passed / total) * 100
        
        if score >= 90:
            level = "A - Excellent"
        elif score >= 80:
            level = "B - Good"
        elif score >= 70:
            level = "C - Acceptable"
        elif score >= 60:
            level = "D - Needs Improvement"
        else:
            level = "F - Critical"
        
        return {
            "score": round(score, 2),
            "level": level,
            "total_checks": total,
            "passed": passed,
            "failed": failed
        }


def check_compliance(framework: str, data: Dict) -> Dict:
    """Función principal de verificación"""
    checker = ComplianceChecker(framework)
    
    if framework == "owasp":
        results = checker.check_web_headers(data.get("headers", {}))
    elif framework == "cis":
        results = checker.check_linux_system(data.get("system_info", {}))
    else:
        results = []
    
    score = checker.calculate_compliance_score(results)
    
    return {
        "framework": framework,
        "results": results,
        "score": score,
        "timestamp": datetime.now().isoformat()
    }


def generate_compliance_report(results: List[Dict], framework: str) -> str:
    """Genera reporte de compliance en markdown"""
    checker = ComplianceChecker(framework)
    score = checker.calculate_compliance_score(results)
    
    md = f"# Reporte de Compliance - {framework.upper()}\n\n"
    md += f"**Puntuación:** {score['score']}%\n"
    md += f"**Nivel:** {score['level']}\n"
    md += f"**Total de Verificaciones:** {score['total_checks']}\n"
    md += f"**Pasadas:** {score['passed']} | **Fallidas:** {score['failed']}\n\n"
    
    md += "## Resultados Detallados\n\n"
    md += "| ID | Verificación | Severidad | Estado |\n"
    md += "|---|---|---|---|\n"
    
    for result in results:
        status_icon = "OK" if result.get("status") == "pass" else "FAIL" if result.get("status") == "fail" else "??"
        md += f"| {result.get('id')} | {result.get('title')} | {result.get('severity')} | {status_icon} |\n"
    
    return md
