"""Tests for RETRO-Ollama types module."""

import pytest
from src.types import (
    BackendType,
    Finding,
    ModeType,
    ScanResult,
    ScanType,
    SeverityLevel,
    Target,
    ToolConfig,
    Workflow,
    WorkflowStep,
)


class TestEnums:
    """Test enum types."""

    def test_severity_level(self):
        """Test severity levels."""
        assert SeverityLevel.CRITICAL.value == "critical"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.INFO.value == "info"

    def test_scan_type(self):
        """Test scan types."""
        assert ScanType.QUICK.value == "quick"
        assert ScanType.FULL.value == "full"
        assert ScanType.VULN.value == "vuln"

    def test_backend_type(self):
        """Test backend types."""
        assert BackendType.OLLAMA.value == "ollama"
        assert BackendType.LMSTUDIO.value == "lmstudio"
        assert BackendType.LLAMACPP.value == "llamacpp"

    def test_mode_type(self):
        """Test mode types."""
        assert ModeType.AUTONOMOUS.value == "autonomous"
        assert ModeType.PENTESTER.value == "pentester"
        assert ModeType.BLUE.value == "blue"


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_scan_result_creation(self):
        """Create a scan result."""
        result = ScanResult(
            target="192.168.1.1",
            scan_type=ScanType.QUICK,
            status="completed",
        )
        assert result.target == "192.168.1.1"
        assert result.scan_type == ScanType.QUICK
        assert result.status == "completed"
        assert result.open_ports == []

    def test_scan_result_with_ports(self):
        """Create scan result with ports."""
        result = ScanResult(
            target="192.168.1.1",
            scan_type=ScanType.FULL,
            status="completed",
            open_ports=[
                {"port": 22, "protocol": "tcp", "service": "ssh"},
                {"port": 80, "protocol": "tcp", "service": "http"},
            ],
        )
        assert len(result.open_ports) == 2


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_creation(self):
        """Create a finding."""
        finding = Finding(
            title="SQL Injection",
            description="SQL Injection vulnerability found",
            severity=SeverityLevel.HIGH,
            cvss=8.5,
        )
        assert finding.title == "SQL Injection"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.cvss == 8.5


class TestTarget:
    """Test Target dataclass."""

    def test_target_creation(self):
        """Create a target."""
        target = Target(
            value="example.com",
            target_type="domain",
        )
        assert target.value == "example.com"
        assert target.target_type == "domain"
        assert target.is_private is False


class TestToolConfig:
    """Test ToolConfig dataclass."""

    def test_tool_config_creation(self):
        """Create a tool config."""
        tool = ToolConfig(
            name="nmap",
            command="nmap",
            args=["-sV"],
            enabled=True,
            timeout=30,
        )
        assert tool.name == "nmap"
        assert tool.enabled is True
        assert tool.timeout == 30


class TestWorkflow:
    """Test Workflow dataclass."""

    def test_workflow_creation(self):
        """Create a workflow."""
        step = WorkflowStep(
            name="nmap_scan",
            tool="nmap",
            args={"target": "192.168.1.1"},
        )
        workflow = Workflow(
            name="recon",
            description="Reconnaissance workflow",
            steps=[step],
        )
        assert workflow.name == "recon"
        assert len(workflow.steps) == 1
        assert workflow.steps[0].tool == "nmap"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
