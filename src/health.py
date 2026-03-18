"""Health check system for RETRO-Ollama."""

import os
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from src.config.settings import BASE_DIR
from src.logging_config import get_logger

logger = get_logger("ptai.health")


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    name: str
    status: str  # "healthy", "degraded", "unhealthy"
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class HealthCheck:
    """Base health check."""

    def __init__(self, name: str, critical: bool = True):
        self.name = name
        self.critical = critical

    def check(self) -> HealthCheckResult:
        """Run the health check."""
        raise NotImplementedError


class OllamaHealthCheck(HealthCheck):
    """Check Ollama connection."""

    def __init__(self, host: str = "localhost:11434"):
        super().__init__("ollama", critical=True)
        self.host = host

    def check(self) -> HealthCheckResult:
        try:
            import requests
            response = requests.get(f"http://{self.host}/api/tags", timeout=5)
            if response.status_code == 200:
                return HealthCheckResult(
                    name=self.name,
                    status="healthy",
                    message="Ollama is running",
                    details={"host": self.host},
                )
            else:
                return HealthCheckResult(
                    name=self.name,
                    status="degraded",
                    message=f"Ollama returned status {response.status_code}",
                    details={"host": self.host},
                )
        except ImportError:
            return HealthCheckResult(
                name=self.name,
                status="degraded",
                message="requests library not available",
            )
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status="unhealthy",
                message=f"Cannot connect to Ollama: {e}",
                details={"host": self.host},
            )


class DirectoryHealthCheck(HealthCheck):
    """Check if required directories exist."""

    def __init__(self, directories: List[str]):
        super().__init__("directories", critical=False)
        self.directories = directories

    def check(self) -> HealthCheckResult:
        missing = []
        existing = []
        
        for dir_path in self.directories:
            path = Path(dir_path)
            if path.exists():
                existing.append(str(path))
            else:
                missing.append(str(path))
        
        if missing:
            return HealthCheckResult(
                name=self.name,
                status="degraded",
                message=f"Missing directories: {', '.join(missing)}",
                details={"existing": existing, "missing": missing},
            )
        
        return HealthCheckResult(
            name=self.name,
            status="healthy",
            message="All required directories exist",
            details={"directories": existing},
        )


class ToolHealthCheck(HealthCheck):
    """Check if required tools are available."""

    def __init__(self, tools: List[str]):
        super().__init__("tools", critical=False)
        self.tools = tools

    def check(self) -> HealthCheckResult:
        available = []
        missing = []
        
        for tool in self.tools:
            if self._is_tool_available(tool):
                available.append(tool)
            else:
                missing.append(tool)
        
        if missing:
            return HealthCheckResult(
                name=self.name,
                status="degraded",
                message=f"Missing tools: {', '.join(missing)}",
                details={"available": available, "missing": missing},
            )
        
        return HealthCheckResult(
            name=self.name,
            status="healthy",
            message="All required tools available",
            details={"tools": available},
        )

    def _is_tool_available(self, tool: str) -> bool:
        """Check if a tool is available."""
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["where", tool],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            else:
                result = subprocess.run(
                    ["which", tool],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            return result.returncode == 0
        except Exception:
            return False


class NetworkHealthCheck(HealthCheck):
    """Check network connectivity."""

    def __init__(self, hosts: List[str] = None):
        super().__init__("network", critical=False)
        self.hosts = hosts or ["8.8.8.8", "1.1.1.1"]

    def check(self) -> HealthCheckResult:
        reachable = []
        unreachable = []
        
        for host in self.hosts:
            if self._is_reachable(host):
                reachable.append(host)
            else:
                unreachable.append(host)
        
        if not reachable:
            return HealthCheckResult(
                name=self.name,
                status="unhealthy",
                message="No network connectivity",
                details={"checked": self.hosts},
            )
        
        if unreachable:
            return HealthCheckResult(
                name=self.name,
                status="degraded",
                message=f"Some hosts unreachable: {', '.join(unreachable)}",
                details={"reachable": reachable, "unreachable": unreachable},
            )
        
        return HealthCheckResult(
            name=self.name,
            status="healthy",
            message="Network connectivity OK",
            details={"hosts": reachable},
        )

    def _is_reachable(self, host: str) -> bool:
        """Check if host is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, 53))
            sock.close()
            return result == 0
        except Exception:
            return False


class APIKeysHealthCheck(HealthCheck):
    """Check API keys configuration."""

    def __init__(self):
        super().__init__("api_keys", critical=False)

    def check(self) -> HealthCheckResult:
        from src.config.settings import check_api_keys
        
        keys = check_api_keys()
        configured = [k for k, v in keys.items() if v]
        missing = [k for k, v in keys.items() if not v]
        
        if not configured:
            return HealthCheckResult(
                name=self.name,
                status="degraded",
                message="No API keys configured",
                details={"missing": missing},
            )
        
        if missing:
            return HealthCheckResult(
                name=self.name,
                status="healthy",
                message=f"API keys configured: {', '.join(configured)}",
                details={"configured": configured, "missing": missing},
            )
        
        return HealthCheckResult(
            name=self.name,
            status="healthy",
            message="All API keys configured",
            details={"configured": configured},
        )


class DiskSpaceHealthCheck(HealthCheck):
    """Check disk space."""

    def __init__(self, min_free_gb: float = 1.0):
        super().__init__("disk_space", critical=True)
        self.min_free_gb = min_free_gb

    def check(self) -> HealthCheckResult:
        try:
            import shutil
            stat = shutil.disk_usage(BASE_DIR)
            free_gb = stat.free / (1024**3)
            
            if free_gb < self.min_free_gb:
                return HealthCheckResult(
                    name=self.name,
                    status="degraded",
                    message=f"Low disk space: {free_gb:.2f}GB free",
                    details={"free_gb": round(free_gb, 2), "total_gb": round(stat.total / (1024**3), 2)},
                )
            
            return HealthCheckResult(
                name=self.name,
                status="healthy",
                message=f"Disk space OK: {free_gb:.2f}GB free",
                details={"free_gb": round(free_gb, 2)},
            )
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status="degraded",
                message=f"Cannot check disk space: {e}",
            )


class HealthCheckSuite:
    """Collection of health checks."""

    def __init__(self):
        self.checks: List[HealthCheck] = []

    def add_check(self, check: HealthCheck) -> "HealthCheckSuite":
        """Add a health check."""
        self.checks.append(check)
        return self

    def run_all(self) -> List[HealthCheckResult]:
        """Run all health checks."""
        results = []
        for check in self.checks:
            try:
                result = check.check()
                results.append(result)
            except Exception as e:
                results.append(HealthCheckResult(
                    name=check.name,
                    status="unhealthy",
                    message=f"Check failed: {e}",
                ))
        return results

    def get_status(self) -> str:
        """Get overall status."""
        results = self.run_all()
        
        if any(r.status == "unhealthy" for r in results):
            if any(r.critical and r.status == "unhealthy" for r in results):
                return "unhealthy"
            return "degraded"
        
        if any(r.status == "degraded" for r in results):
            return "degraded"
        
        return "healthy"


def create_default_suite() -> HealthCheckSuite:
    """Create default health check suite."""
    suite = HealthCheckSuite()
    
    suite.add_check(OllamaHealthCheck())
    suite.add_check(DirectoryHealthCheck([
        str(BASE_DIR / "output"),
        str(BASE_DIR / "reports"),
        str(BASE_DIR / "scans"),
    ]))
    suite.add_check(DiskSpaceHealthCheck())
    suite.add_check(NetworkHealthCheck())
    suite.add_check(APIKeysHealthCheck())
    
    return suite


def run_health_checks() -> Dict[str, Any]:
    """Run all health checks and return results."""
    suite = create_default_suite()
    results = suite.run_all()
    
    return {
        "status": suite.get_status(),
        "timestamp": datetime.now().isoformat(),
        "checks": [
            {
                "name": r.name,
                "status": r.status,
                "message": r.message,
                "details": r.details,
            }
            for r in results
        ],
    }
