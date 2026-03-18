import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.threat_intel import (
    ThreatIntelligence,
    quick_ioc_check,
    THREAT_CATEGORIES,
    IOC_PATTERNS,
    MALICIOUS_EXTENSIONS,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_PROCESSES
)


class TestThreatIntelligence:
    """Tests para ThreatIntelligence"""

    def test_threat_intel_creation(self):
        """Crear instancia"""
        ti = ThreatIntelligence()
        assert ti is not None

    def test_extract_iocs_ip(self):
        """Extraer IPs"""
        ti = ThreatIntelligence()
        text = "Attacker IP: 192.168.1.100 and 10.0.0.5"
        iocs = ti.extract_iocs(text)
        assert "ipv4" in iocs

    def test_extract_iocs_domain(self):
        """Extraer dominios"""
        ti = ThreatIntelligence()
        text = "Malicious domain: evil.com and phishing.net"
        iocs = ti.extract_iocs(text)
        assert "domain" in iocs

    def test_extract_iocs_email(self):
        """Extraer emails"""
        ti = ThreatIntelligence()
        text = "Contact: attacker@evil.com"
        iocs = ti.extract_iocs(text)
        assert "email" in iocs

    def test_extract_iocs_hash(self):
        """Extraer hashes"""
        ti = ThreatIntelligence()
        text = "Hash: 5d41402abc4b2a76b9719d911017c592"
        iocs = ti.extract_iocs(text)
        assert "md5" in iocs

    def test_extract_iocs_url(self):
        """Extraer URLs"""
        ti = ThreatIntelligence()
        text = "Visit https://evil.com/malware"
        iocs = ti.extract_iocs(text)
        assert "url" in iocs

    def test_extract_iocs_cve(self):
        """Extraer CVEs"""
        ti = ThreatIntelligence()
        text = "CVE-2021-44228 is critical"
        iocs = ti.extract_iocs(text)
        assert "cve" in iocs

    def test_check_ip_reputation_private(self):
        """IP privada"""
        ti = ThreatIntelligence()
        result = ti.check_ip_reputation("192.168.1.1")
        assert result["reputation"] == "private"

    def test_check_ip_reputation_localhost(self):
        """Localhost"""
        ti = ThreatIntelligence()
        result = ti.check_ip_reputation("127.0.0.1")
        assert result["reputation"] == "private"

    def test_check_hash_reputation(self):
        """Verificar hash"""
        ti = ThreatIntelligence()
        result = ti.check_hash_reputation("5d41402abc4b2a76b9719d911017c592")
        assert "hash_type" in result

    def test_check_domain_reputation(self):
        """Verificar dominio"""
        ti = ThreatIntelligence()
        result = ti.check_domain_reputation("free-download.xyz")
        assert "reputation" in result

    def test_check_domain_reputation_suspicious(self):
        """Dominio sospechoso"""
        ti = ThreatIntelligence()
        result = ti.check_domain_reputation("hack-free.xyz")
        assert result["reputation"] == "suspicious"

    def test_classify_threat_malware(self):
        """Clasificar malware"""
        ti = ThreatIntelligence()
        threats = ti.classify_threat("Found emotet trojan on system")
        assert len(threats) > 0

    def test_classify_threat_phishing(self):
        """Clasificar phishing"""
        ti = ThreatIntelligence()
        threats = ti.classify_threat("Phishing email detected")
        assert len(threats) > 0

    def test_analyze_file_indicators(self):
        """Analizar archivo"""
        ti = ThreatIntelligence()
        result = ti.analyze_file_indicators("malware.exe")
        assert result["suspicious"] is True

    def test_analyze_file_indicators_safe(self):
        """Archivo seguro"""
        ti = ThreatIntelligence()
        result = ti.analyze_file_indicators("document.pdf")
        assert result["suspicious"] is False

    def test_check_process_safety(self):
        """Proceso malicioso"""
        ti = ThreatIntelligence()
        result = ti.check_process_safety("mimikatz")
        assert result["is_malicious"] is True

    def test_check_process_safety_safe(self):
        """Proceso seguro"""
        ti = ThreatIntelligence()
        result = ti.check_process_safety("notepad.exe")
        assert result["is_malicious"] is False

    def test_quick_ioc_check(self):
        """Verificación rápida"""
        result = quick_ioc_check("IP: 192.168.1.1")
        assert "iocs" in result
        assert "threats" in result


class TestThreatCategories:
    """Tests para categorías de amenazas"""

    def test_malware_categories_exist(self):
        """Categorías de malware"""
        assert "malware" in THREAT_CATEGORIES

    def test_attack_patterns_exist(self):
        """Patrones de ataque"""
        assert "attack_patterns" in THREAT_CATEGORIES

    def test_ioc_patterns_exist(self):
        """Patrones IOC"""
        assert "ipv4" in IOC_PATTERNS
        assert "domain" in IOC_PATTERNS
        assert "sha256" in IOC_PATTERNS


class TestIOCPatterns:
    """Tests para patrones IOC"""

    def test_malicious_extensions(self):
        """Extensiones maliciosas"""
        assert ".exe" in MALICIOUS_EXTENSIONS
        assert ".dll" in MALICIOUS_EXTENSIONS

    def test_suspicious_extensions(self):
        """Extensiones sospechosas"""
        assert ".ps1" in SUSPICIOUS_EXTENSIONS
        assert ".vbs" in SUSPICIOUS_EXTENSIONS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
