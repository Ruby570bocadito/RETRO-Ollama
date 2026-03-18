import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.compliance import (
    ComplianceChecker,
    check_compliance,
    generate_compliance_report,
    COMPLIANCE_CHECKS
)


class TestComplianceChecker:
    """Tests para ComplianceChecker"""

    def test_compliance_checks_exist(self):
        """Verifica que existan los checks"""
        assert "cis_benchmarks" in COMPLIANCE_CHECKS
        assert "owasp" in COMPLIANCE_CHECKS
        assert "pci_dss" in COMPLIANCE_CHECKS
        assert "nist" in COMPLIANCE_CHECKS

    def test_owasp_headers_exist(self):
        """Verifica headers OWASP"""
        checks = COMPLIANCE_CHECKS["owasp"]["headers"]
        assert len(checks) > 0
        assert any(h["id"] == "OWASP-H-1" for h in checks)

    def test_cis_linux_checks(self):
        """Verifica checks CIS Linux"""
        checks = COMPLIANCE_CHECKS["cis_benchmarks"]["linux"]
        assert len(checks) > 0

    def test_checker_creation(self):
        """Crear checker"""
        checker = ComplianceChecker("owasp")
        assert checker.framework == "owasp"

    def test_check_web_headers_pass(self):
        """Headers que pasan"""
        checker = ComplianceChecker("owasp")
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY"
        }
        results = checker.check_web_headers(headers)
        assert len(results) > 0

    def test_check_web_headers_fail(self):
        """Headers que fallan"""
        checker = ComplianceChecker("owasp")
        headers = {}
        results = checker.check_web_headers(headers)
        assert len(results) > 0

    def test_calculate_compliance_score(self):
        """Calcular puntuación"""
        checker = ComplianceChecker("owasp")
        results = [
            {"id": "1", "status": "pass"},
            {"id": "2", "status": "pass"},
            {"id": "3", "status": "fail"}
        ]
        score = checker.calculate_compliance_score(results)
        assert score["score"] > 0
        assert score["total_checks"] == 3

    def test_calculate_compliance_all_pass(self):
        """Todos pasan"""
        checker = ComplianceChecker("owasp")
        results = [
            {"id": "1", "status": "pass"},
            {"id": "2", "status": "pass"}
        ]
        score = checker.calculate_compliance_score(results)
        assert score["score"] == 100

    def test_check_compliance_function(self):
        """Función principal check_compliance"""
        result = check_compliance("owasp", {"headers": {}})
        assert "results" in result
        assert "score" in result
        assert result["framework"] == "owasp"

    def test_generate_compliance_report(self):
        """Generar reporte"""
        results = [
            {"id": "OWASP-H-1", "title": "HSTS", "severity": "high", "status": "pass"},
            {"id": "OWASP-H-2", "title": "X-Content-Type", "severity": "medium", "status": "fail"}
        ]
        report = generate_compliance_report(results, "owasp")
        assert "Compliance" in report
        assert "OWASP" in report
        assert "HSTS" in report


class TestComplianceContent:
    """Tests para contenido de compliance"""

    def test_pci_dss_requirements(self):
        """Requisitos PCI DSS"""
        reqs = COMPLIANCE_CHECKS["pci_dss"]["requirements"]
        assert len(reqs) > 0

    def test_nist_controls(self):
        """Controles NIST"""
        controls = COMPLIANCE_CHECKS["nist"]["controls"]
        assert len(controls) > 0

    def test_severity_levels(self):
        """Niveles de severidad"""
        linux = COMPLIANCE_CHECKS["cis_benchmarks"]["linux"]
        severities = set(ch["severity"] for ch in linux)
        assert "critical" in severities
        assert "high" in severities


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
