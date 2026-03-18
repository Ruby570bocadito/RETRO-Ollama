"""Tests for health module."""

import pytest
from src.health import (
    HealthCheckResult,
    DiskSpaceHealthCheck,
    DirectoryHealthCheck,
    ToolHealthCheck,
    APIKeysHealthCheck,
    HealthCheckSuite,
    create_default_suite,
    run_health_checks,
)


class TestHealthCheckResult:
    """Test HealthCheckResult."""

    def test_creation(self):
        """Test creating a health check result."""
        result = HealthCheckResult(
            name="test",
            status="healthy",
            message="All good",
        )
        assert result.name == "test"
        assert result.status == "healthy"
        assert result.message == "All good"


class TestDiskSpaceHealthCheck:
    """Test DiskSpaceHealthCheck."""

    def test_check(self):
        """Test disk space check."""
        check = DiskSpaceHealthCheck(min_free_gb=0.1)
        result = check.check()
        assert result.name == "disk_space"
        assert result.status in ["healthy", "degraded"]


class TestDirectoryHealthCheck:
    """Test DirectoryHealthCheck."""

    def test_check_existing(self):
        """Test directory check with existing directories."""
        check = DirectoryHealthCheck(["."])
        result = check.check()
        assert result.name == "directories"
        assert result.status == "healthy"

    def test_check_missing(self):
        """Test directory check with missing directories."""
        check = DirectoryHealthCheck(["/nonexistent_directory_12345"])
        result = check.check()
        assert result.name == "directories"
        assert result.status == "degraded"


class TestToolHealthCheck:
    """Test ToolHealthCheck."""

    def test_check_python(self):
        """Test tool check with python."""
        check = ToolHealthCheck(["python"])
        result = check.check()
        assert result.name == "tools"
        assert result.status == "healthy"

    def test_check_nonexistent(self):
        """Test tool check with nonexistent tool."""
        check = ToolHealthCheck(["nonexistent_tool_xyz123"])
        result = check.check()
        assert result.name == "tools"
        assert result.status == "degraded"


class TestAPIKeysHealthCheck:
    """Test APIKeysHealthCheck."""

    def test_check(self):
        """Test API keys check."""
        check = APIKeysHealthCheck()
        result = check.check()
        assert result.name == "api_keys"
        assert result.status in ["healthy", "degraded"]


class TestHealthCheckSuite:
    """Test HealthCheckSuite."""

    def test_create_suite(self):
        """Test creating health check suite."""
        suite = HealthCheckSuite()
        assert len(suite.checks) == 0

    def test_add_check(self):
        """Test adding check to suite."""
        suite = HealthCheckSuite()
        check = DiskSpaceHealthCheck()
        suite.add_check(check)
        assert len(suite.checks) == 1

    def test_run_all(self):
        """Test running all checks."""
        suite = HealthCheckSuite()
        suite.add_check(DiskSpaceHealthCheck())
        suite.add_check(DirectoryHealthCheck(["."]))
        results = suite.run_all()
        assert len(results) == 2

    def test_get_status_healthy(self):
        """Test getting healthy status."""
        suite = HealthCheckSuite()
        suite.add_check(DiskSpaceHealthCheck(min_free_gb=0.001))
        status = suite.get_status()
        assert status in ["healthy", "degraded"]


class TestRunHealthChecks:
    """Test run_health_checks function."""

    def test_run_health_checks(self):
        """Test running all health checks."""
        results = run_health_checks()
        assert "status" in results
        assert "timestamp" in results
        assert "checks" in results
        assert len(results["checks"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
