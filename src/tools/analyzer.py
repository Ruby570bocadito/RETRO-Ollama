from typing import Dict, List, Optional, Any
import re


class Finding:
    def __init__(self, title: str, severity: str, description: str, 
                 evidence: str = "", remediation: str = "", cve: str = ""):
        self.title = title
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.cve = cve
        self.tags: List[str] = []
    
    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve": self.cve,
            "tags": self.tags
        }
    
    def add_tag(self, tag: str):
        if tag not in self.tags:
            self.tags.append(tag)


class ScanAnalyzer:
    def __init__(self, scan_output: str, scan_type: str = "nmap"):
        self.scan_output = scan_output
        self.scan_type = scan_type
        self.findings: List[Finding] = []
    
    def analyze(self) -> List[Finding]:
        if self.scan_type == "nmap":
            self._analyze_nmap()
        elif self.scan_type == "nikto":
            self._analyze_nikto()
        elif self.scan_type == "nuclei":
            self._analyze_nuclei()
        return self.findings
    
    def _analyze_nmap(self):
        ports = re.findall(r'(\d+)/(tcp|udp)\s+(open|closed)', self.scan_output)
        
        for port, proto, state in ports:
            if state == "open":
                self._check_common_services(int(port), proto)
        
        if "OS details:" in self.scan_output or "OS guess:" in self.scan_output:
            self.findings.append(Finding(
                title="Detección de Sistema Operativo",
                severity="info",
                description="Se detectó el sistema operativo del objetivo",
                remediation="Documentar el SO detectado para ajustar técnicas de ataque"
            ))
        
        if "script:" in self.scan_output.lower():
            self.findings.append(Finding(
                title="Scripts NSE ejecutados",
                severity="info",
                description="Se ejecutaron scripts de Nmap",
                remediation="Revisar los resultados de los scripts"
            ))
    
    def _check_common_services(self, port: int, proto: str):
        dangerous_services = {
            21: ("FTP Anónimo", "high", "FTP permite acceso anónimo", "Deshabilitar acceso anónimo o usar FTPS"),
            23: ("Telnet", "critical", "Telnet transmite datos en texto plano", "Usar SSH en su lugar"),
            25: ("SMTP", "medium", "Servicio de correo expuesto", "Restringir relay"),
            135: ("RPC", "high", "Windows RPC expuesto", "Bloquear en firewall"),
            139: ("NetBIOS", "high", "NetBIOS expuesto", "Deshabilitar NetBIOS"),
            445: ("SMB", "critical", "SMB expuesto", "Bloquear SMB o usar SMB signing"),
            1433: ("MSSQL", "high", "SQL Server expuesto", "Restringir acceso por IP"),
            3306: ("MySQL", "high", "MySQL expuesto", "Restringir acceso remoto"),
            3389: ("RDP", "critical", "RDP expuesto", "Usar VPN + MFA"),
            5432: ("PostgreSQL", "high", "PostgreSQL expuesto", "Restringir acceso"),
            5900: ("VNC", "high", "VNC sin cifrar", "Usar SSH tunneling"),
            6379: ("Redis", "critical", "Redis sin auth", "Configurar contraseña"),
            27017: ("MongoDB", "critical", "MongoDB sin auth", "Configurar auth"),
        }
        
        if port in dangerous_services:
            name, severity, desc, remediation = dangerous_services[port]
            self.findings.append(Finding(
                title=f"Servicio Peligroso: {name}",
                severity=severity,
                description=desc,
                evidence=f"Puerto {port}/{proto} abierto",
                remediation=remediation
            ))
    
    def _analyze_nikto(self):
        vulns = re.findall(r'\+ ([^\n]+)', self.scan_output)
        
        for vuln in vulns:
            if any(x in vuln.lower() for x in ["vulnerability", "error", "issue", "found"]):
                self.findings.append(Finding(
                    title=f"Resultado Nikto: {vuln[:50]}",
                    severity="medium",
                    description=vuln,
                    remediation="Revisar y remediar según documentación Nikto"
                ))
    
    def _analyze_nuclei(self):
        matches = re.findall(r'\[([^\]]+)\]\[([^\]]+)\]', self.scan_output)
        
        for severity, info in matches:
            sev = "medium"
            if "critical" in severity.lower():
                sev = "critical"
            elif "high" in severity.lower():
                sev = "high"
            elif "low" in severity.lower():
                sev = "low"
            
            self.findings.append(Finding(
                title=f"Nuclei: {info[:50]}",
                severity=sev,
                description=f"{severity} - {info}",
                remediation="Revisar template de Nuclei"
            ))
    
    def get_summary(self) -> Dict:
        return {
            "total_findings": len(self.findings),
            "by_severity": {
                "critical": len([f for f in self.findings if f.severity == "critical"]),
                "high": len([f for f in self.findings if f.severity == "high"]),
                "medium": len([f for f in self.findings if f.severity == "medium"]),
                "low": len([f for f in self.findings if f.severity == "low"]),
                "info": len([f for f in self.findings if f.severity == "info"])
            }
        }


def analyze_scan_output(output: str, scan_type: str = "nmap") -> Dict:
    """Analiza salida de escaneo y retorna hallazgos"""
    analyzer = ScanAnalyzer(output, scan_type)
    findings = analyzer.analyze()
    summary = analyzer.get_summary()
    
    return {
        "findings": [f.to_dict() for f in findings],
        "summary": summary
    }


def parse_nmap_service_banner(banner: str) -> Dict:
    """Parsea banner de servicio Nmap"""
    result = {
        "service": None,
        "version": None,
        "product": None,
        "extrainfo": None
    }
    
    match = re.search(r'([^/]+)/?([^ ]+)? (.+)', banner)
    if match:
        result["service"] = match.group(1)
        result["version"] = match.group(2)
        result["extrainfo"] = match.group(3)
    
    return result


def identify_vulnerable_versions(service: str, version: str) -> List[str]:
    """Identifica versiones vulnerables conocidas"""
    cve_map = {
        "openssh": {
            "7.4": ["CVE-2017-15906"],
            "7.9": ["CVE-2019-6109"],
            "8.2": ["CVE-2020-15778"]
        },
        "apache": {
            "2.4.29": ["CVE-2017-15710"],
            "2.4.38": ["CVE-2019-0211"]
        },
        "nginx": {
            "1.14": ["CVE-2017-7529"],
            "1.16": ["CVE-2019-9511"]
        },
        "mysql": {
            "5.7": ["CVE-2018-2562"],
            "8.0": ["CVE-2020-2574"]
        }
    }
    
    cves = []
    service_lower = service.lower()
    
    if service_lower in cve_map:
        for ver, cve_list in cve_map.items():
            if ver in version:
                cves.extend(cve_list)
    
    return cves


def generate_risk_score(findings: List[Dict]) -> Dict:
    """Calcula puntuación de riesgo basada en hallazgos"""
    weights = {
        "critical": 10,
        "high": 7.5,
        "medium": 5,
        "low": 2.5,
        "info": 0
    }
    
    score = 0
    for f in findings:
        severity = f.get("severity", "info").lower()
        score += weights.get(severity, 0)
    
    max_score = len(findings) * 10
    percentage = (score / max_score * 100) if max_score > 0 else 0
    
    risk_level = "Bajo"
    if percentage >= 70:
        risk_level = "Crítico"
    elif percentage >= 50:
        risk_level = "Alto"
    elif percentage >= 30:
        risk_level = "Medio"
    
    return {
        "score": round(score, 2),
        "max_score": max_score,
        "percentage": round(percentage, 2),
        "risk_level": risk_level,
        "finding_count": len(findings)
    }


def extract_cves_from_text(text: str) -> List[str]:
    """Extrae CVEs de un texto"""
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    return re.findall(cve_pattern, text, re.IGNORECASE)


def parse_nmap_xml(xml_output: str) -> Dict:
    """Parsea salida XML de Nmap"""
    result = {
        "hosts": [],
        "ports": [],
        "services": []
    }
    
    host_matches = re.findall(r'<host[^>]*>(.*?)</host>', xml_output, re.DOTALL)
    for host in host_matches:
        addr = re.search(r'<address addr="([^"]+)"', host)
        if addr:
            result["hosts"].append(addr.group(1))
    
    port_matches = re.findall(r'<port protocol="([^"]+)" portid="(\d+)"[^>]*>.*?<state state="([^"]+)"', host)
    for proto, port, state in port_matches:
        if state == "open":
            result["ports"].append({"port": int(port), "protocol": proto})
    
    return result


def extract_domains_from_text(text: str) -> List[str]:
    """Extrae dominios de un texto"""
    domain_pattern = r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b'
    domains = re.findall(domain_pattern, text)
    return list(set(domains))


def extract_urls_from_text(text: str) -> List[str]:
    """Extrae URLs de un texto"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)


def parse_ssl_certificate(cert_text: str) -> Dict:
    """Parsea certificado SSL"""
    result = {
        "subject": None,
        "issuer": None,
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None
    }
    
    subject_match = re.search(r'Subject:\s*(.+?)(?:\n|$)', cert_text)
    if subject_match:
        result["subject"] = subject_match.group(1).strip()
    
    issuer_match = re.search(r'Issuer:\s*(.+?)(?:\n|$)', cert_text)
    if issuer_match:
        result["issuer"] = issuer_match.group(1).strip()
    
    return result


def analyze_http_headers(headers: Dict) -> List[Finding]:
    """Analiza headers HTTP"""
    findings = []
    
    security_headers = {
        "X-Frame-Options": "Protege contra clickjacking",
        "X-Content-Type-Options": "Previene MIME sniffing",
        "Strict-Transport-Security": "Fuerza HTTPS",
        "Content-Security-Policy": "Previene XSS",
        "X-XSS-Protection": "Protección XSS legacy"
    }
    
    for header, description in security_headers.items():
        if header not in headers:
            findings.append(Finding(
                title=f"Header de seguridad faltante: {header}",
                severity="medium",
                description=f"{description}",
                remediation=f"Implementar {header}"
            ))
    
    if headers.get("Server"):
        findings.append(Finding(
            title="Banner de servidor expuesto",
            severity="low",
            description=f"Server: {headers.get('Server')}",
            remediation="Ocultar información del servidor"
        ))
    
    return findings


def compare_scans(old_output: str, new_output: str) -> Dict:
    """Compara dos escaneos"""
    old_ports = set(re.findall(r'(\d+)/(tcp|udp)\s+open', old_output))
    new_ports = set(re.findall(r'(\d+)/(tcp|udp)\s+open', new_output))
    
    added = new_ports - old_ports
    removed = old_ports - new_ports
    
    return {
        "added_ports": list(added),
        "removed_ports": list(removed),
        "total_added": len(added),
        "total_removed": len(removed)
    }


def sanitize_output(output: str, sensitive_patterns: List[str] = None) -> str:
    """Limpia salida sensibles"""
    if sensitive_patterns is None:
        sensitive_patterns = [
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
            (r'password[^\s]*', '[PASSWORD]'),
            (r'api[_-]?key[^\s]*', '[API_KEY]'),
            (r'token[^\s]*', '[TOKEN]')
        ]
    
    sanitized = output
    for pattern, replacement in sensitive_patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
    
    return sanitized


def format_finding_markdown(finding: Dict) -> str:
    """Formatea finding como markdown"""
    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "🔵"
    }
    
    emoji = severity_emoji.get(finding.get("severity", "info"), "⚪")
    
    md = f"### {emoji} {finding.get('title', 'Untitled')}\n\n"
    md += f"**Severidad:** {finding.get('severity', 'N/A')}\n\n"
    md += f"**Descripción:** {finding.get('description', 'N/A')}\n\n"
    
    if finding.get("evidence"):
        md += f"**Evidencia:**\n```\n{finding.get('evidence')}\n```\n\n"
    
    if finding.get("remediation"):
        md += f"**Remediación:** {finding.get('remediation')}\n\n"
    
    if finding.get("cve"):
        md += f"**CVE:** `{finding.get('cve')}`\n\n"
    
    return md
