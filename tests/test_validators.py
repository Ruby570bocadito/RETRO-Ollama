"""Tests for validators module."""

import pytest
from pydantic import ValidationError

from src.validators import (
    CVERequest,
    Domain,
    IPAddress,
    ReportRequest,
    ScanRequest,
    URL,
    validate_target,
    WorkflowRequest,
)


class TestIPAddress:
    """Test IPAddress validation."""

    def test_valid_ipv4(self):
        """Test valid IPv4."""
        ip = IPAddress(value="192.168.1.1")
        assert ip.value == "192.168.1.1"

    def test_valid_private_ip(self):
        """Test private IP detection."""
        ip = IPAddress(value="10.0.0.1")
        assert ip.is_private() is True

    def test_public_ip(self):
        """Test public IP."""
        ip = IPAddress(value="8.8.8.8")
        assert ip.is_private() is False

    def test_invalid_ip(self):
        """Test invalid IP."""
        with pytest.raises(ValidationError):
            IPAddress(value="invalid")


class TestDomain:
    """Test Domain validation."""

    def test_valid_domain(self):
        """Test valid domain."""
        domain = Domain(value="example.com")
        assert domain.value == "example.com"

    def test_valid_subdomain(self):
        """Test valid subdomain."""
        domain = Domain(value="sub.example.com")
        assert domain.value == "sub.example.com"

    def test_invalid_domain(self):
        """Test invalid domain."""
        with pytest.raises(ValidationError):
            Domain(value="invalid..com")


class TestURL:
    """Test URL validation."""

    def test_valid_url(self):
        """Test valid URL."""
        url = URL(value="https://example.com")
        assert url.value == "https://example.com"

    def test_get_domain(self):
        """Test get domain."""
        url = URL(value="https://example.com/path")
        assert url.get_domain() == "example.com"

    def test_invalid_url(self):
        """Test invalid URL."""
        with pytest.raises(ValidationError):
            URL(value="not-a-url")


class TestScanRequest:
    """Test ScanRequest validation."""

    def test_valid_ip_target(self):
        """Test valid IP target."""
        req = ScanRequest(target="192.168.1.1")
        assert req.target == "192.168.1.1"

    def test_valid_domain_target(self):
        """Test valid domain target."""
        req = ScanRequest(target="example.com")
        assert req.target == "example.com"

    def test_invalid_scan_type(self):
        """Test invalid scan type."""
        with pytest.raises(ValidationError):
            ScanRequest(target="example.com", scan_type="invalid")

    def test_stealth_mode(self):
        """Test stealth mode."""
        req = ScanRequest(target="example.com", stealth=True)
        assert req.stealth is True


class TestCVERequest:
    """Test CVERequest validation."""

    def test_valid_cve_id(self):
        """Test valid CVE ID."""
        req = CVERequest(cve_id="CVE-2021-44228")
        assert req.cve_id == "CVE-2021-44228"

    def test_invalid_cve_id(self):
        """Test invalid CVE ID."""
        with pytest.raises(ValidationError):
            CVERequest(cve_id="invalid")

    def test_no_cve_id(self):
        """Test no CVE ID."""
        req = CVERequest(keyword="log4j")
        assert req.cve_id is None


class TestReportRequest:
    """Test ReportRequest validation."""

    def test_valid_request(self):
        """Test valid request."""
        req = ReportRequest(title="Test Report", target="example.com")
        assert req.title == "Test Report"

    def test_invalid_format(self):
        """Test invalid format."""
        with pytest.raises(ValidationError):
            ReportRequest(title="Test", target="example.com", format="invalid")

    def test_title_too_long(self):
        """Test title too long."""
        with pytest.raises(ValidationError):
            ReportRequest(title="x" * 201, target="example.com")


class TestWorkflowRequest:
    """Test WorkflowRequest validation."""

    def test_valid_workflow(self):
        """Test valid workflow."""
        req = WorkflowRequest(workflow_name="recon", target="example.com")
        assert req.workflow_name == "recon"

    def test_invalid_workflow(self):
        """Test invalid workflow."""
        with pytest.raises(ValidationError):
            WorkflowRequest(workflow_name="invalid", target="example.com")


class TestValidateTarget:
    """Test validate_target function."""

    def test_validate_ip(self):
        """Test IP validation."""
        target_type, result = validate_target("192.168.1.1")
        assert target_type == "ip"
        assert result == "192.168.1.1"

    def test_validate_domain(self):
        """Test domain validation."""
        target_type, result = validate_target("example.com")
        assert target_type == "domain"
        assert result == "example.com"

    def test_validate_url(self):
        """Test URL validation."""
        target_type, result = validate_target("https://example.com")
        assert target_type == "url"

    def test_invalid_target(self):
        """Test invalid target."""
        with pytest.raises(ValueError):
            validate_target("!!invalid!!")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
