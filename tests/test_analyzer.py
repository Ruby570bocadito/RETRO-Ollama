import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.analyzer import (
    Finding,
    ScanAnalyzer,
    analyze_scan_output,
    parse_nmap_service_banner,
    identify_vulnerable_versions,
    generate_risk_score,
    extract_cves_from_text,
    parse_nmap_xml,
    extract_domains_from_text,
    extract_urls_from_text,
    parse_ssl_certificate,
    analyze_http_headers,
    compare_scans,
    sanitize_output,
    format_finding_markdown
)


class TestFinding:
    """Tests para la clase Finding"""

    def test_finding_creation(self):
        """Crear finding"""
        f = Finding("Test", "high", "Description")
        assert f.title == "Test"
        assert f.severity == "high"
        assert f.description == "Description"

    def test_finding_to_dict(self):
        """Convertir a dict"""
        f = Finding("Test", "high", "Desc", "evidence", "fix", "CVE-2021-1234")
        d = f.to_dict()
        assert d["title"] == "Test"
        assert d["cve"] == "CVE-2021-1234"

    def test_finding_add_tag(self):
        """Añadir tags"""
        f = Finding("Test", "high", "Desc")
        f.add_tag("web")
        f.add_tag("web")
        assert "web" in f.tags
        assert len(f.tags) == 1


class TestScanAnalyzer:
    """Tests para ScanAnalyzer"""

    def test_analyze_nmap_with_ports(self):
        """Analizar nmap con puertos"""
        output = "22/tcp open ssh\n80/tcp open http\n445/tcp open microsoft-ds"
        analyzer = ScanAnalyzer(output, "nmap")
        findings = analyzer.analyze()
        assert len(findings) > 0

    def test_analyze_nmap_smb(self):
        """Analizar SMB"""
        output = "445/tcp open microsoft-ds"
        analyzer = ScanAnalyzer(output, "nmap")
        findings = analyzer.analyze()
        assert any("SMB" in f.title for f in findings)

    def test_analyze_nmap_ftp(self):
        """Analizar FTP"""
        output = "21/tcp open ftp"
        analyzer = ScanAnalyzer(output, "nmap")
        findings = analyzer.analyze()
        assert any("FTP" in f.title for f in findings)

    def test_analyze_nikto(self):
        """Analizar Nikto"""
        output = "+ Some vulnerability found"
        analyzer = ScanAnalyzer(output, "nikto")
        findings = analyzer.analyze()
        assert len(findings) > 0

    def test_get_summary(self):
        """Resumen de hallazgos"""
        output = "22/tcp open ssh\n445/tcp open smb"
        analyzer = ScanAnalyzer(output, "nmap")
        analyzer.analyze()
        summary = analyzer.get_summary()
        assert "total_findings" in summary
        assert "by_severity" in summary


class TestAnalyzeFunctions:
    """Tests para funciones de análisis"""

    def test_analyze_scan_output(self):
        """Analizar salida de escaneo"""
        result = analyze_scan_output("22/tcp open ssh", "nmap")
        assert "findings" in result
        assert "summary" in result

    def test_parse_nmap_service_banner(self):
        """Parsear banner"""
        banner = "ssh OpenSSH 7.4"
        result = parse_nmap_service_banner(banner)
        assert "service" in result

    def test_identify_vulnerable_versions(self):
        """Identificar versiones vulnerables"""
        cves = identify_vulnerable_versions("openssh", "7.4")
        assert isinstance(cves, list)

    def test_generate_risk_score(self):
        """Generar puntuación de riesgo"""
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"}
        ]
        result = generate_risk_score(findings)
        assert "score" in result
        assert "risk_level" in result
        assert result["risk_level"] in ["Bajo", "Medio", "Alto", "Crítico"]


class TestExtractors:
    """Tests para extractores"""

    def test_extract_cves(self):
        """Extraer CVEs"""
        text = "Found CVE-2021-44228 and CVE-2022-1234"
        cves = extract_cves_from_text(text)
        assert "CVE-2021-44228" in cves

    def test_extract_domains(self):
        """Extraer dominios"""
        text = "example.com test.org domain.io"
        domains = extract_domains_from_text(text)
        assert len(domains) >= 1

    def test_extract_urls(self):
        """Extraer URLs"""
        text = "Go to https://example.com or http://test.com"
        urls = extract_urls_from_text(text)
        assert len(urls) == 2


class TestSanitization:
    """Tests para sanitización"""

    def test_sanitize_output(self):
        """Limpiar salida"""
        output = "IP: 192.168.1.1 and email: test@example.com"
        sanitized = sanitize_output(output)
        assert "192.168.1.1" not in sanitized
        assert "test@example.com" not in sanitized


class TestFormatting:
    """Tests para formateo"""

    def test_format_finding_markdown(self):
        """Formatear finding como markdown"""
        finding = {
            "title": "Test Finding",
            "severity": "high",
            "description": "Test description",
            "evidence": "test evidence",
            "remediation": "fix it",
            "cve": "CVE-2021-1234"
        }
        md = format_finding_markdown(finding)
        assert "Test Finding" in md
        assert "high" in md


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
