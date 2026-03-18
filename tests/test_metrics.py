import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.metrics import (
    Metric,
    SecurityMetrics,
    security_metrics
)


class TestMetric:
    """Tests para Metric"""

    def test_metric_creation(self):
        """Crear métrica"""
        m = Metric("test", 100, "category")
        assert m.name == "test"
        assert m.value == 100
    
    def test_metric_to_dict(self):
        """Convertir a dict"""
        m = Metric("test", 50)
        d = m.to_dict()
        assert "name" in d
        assert "value" in d


class TestSecurityMetrics:
    """Tests para SecurityMetrics"""

    def test_metrics_creation(self):
        """Crear metrics"""
        sm = SecurityMetrics()
        assert sm is not None

    def test_add_metric(self):
        """Añadir métrica"""
        sm = SecurityMetrics()
        sm.add_metric("test", 100, "category")
        assert len(sm.metrics) == 1

    def test_record_finding(self):
        """Registrar finding"""
        sm = SecurityMetrics()
        sm.record_finding("critical")
        assert sm.findings_by_severity["critical"] == 1

    def test_record_scan(self):
        """Registrar scan"""
        sm = SecurityMetrics()
        sm.record_scan("nmap")
        assert sm.scans_by_type["nmap"] == 1

    def test_record_incident(self):
        """Registrar incidente"""
        sm = SecurityMetrics()
        sm.record_incident("phishing")
        assert sm.incidents_by_type["phishing"] == 1

    def test_get_risk_score(self):
        """Obtener risk score"""
        sm = SecurityMetrics()
        sm.record_finding("critical")
        sm.record_finding("high")
        score = sm.get_risk_score()
        assert score == 17.5

    def test_get_total_findings(self):
        """Total findings"""
        sm = SecurityMetrics()
        sm.record_finding("critical")
        sm.record_finding("medium")
        assert sm.get_total_findings() == 2

    def test_get_summary(self):
        """Resumen"""
        sm = SecurityMetrics()
        sm.record_finding("critical")
        summary = sm.get_summary()
        assert "total_findings" in summary
        assert "risk_score" in summary

    def test_get_trend(self):
        """Tendencia"""
        sm = SecurityMetrics()
        sm.add_metric("test", 100)
        trend = sm.get_trend(7)
        assert isinstance(trend, list)

    def test_generate_dashboard_data(self):
        """Dashboard data"""
        sm = SecurityMetrics()
        sm.record_finding("critical")
        data = sm.generate_dashboard_data()
        assert "summary" in data
        assert "risk_gauge" in data


class TestSecurityMetricsSingleton:
    """Tests para singleton"""

    def test_singleton_exists(self):
        """Existe singleton"""
        assert security_metrics is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
