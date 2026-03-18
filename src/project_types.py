"""Shared types for RETRO-Ollama project."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union

from typing_extensions import TypedDict


class SeverityLevel(str, Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanType(str, Enum):
    """Types of security scans."""
    QUICK = "quick"
    FULL = "full"
    VULN = "vuln"
    WEB = "web"
    DIR = "dir"
    STEALTH = "stealth"
    OS = "os"


class BackendType(str, Enum):
    """Available AI backends."""
    OLLAMA = "ollama"
    LMSTUDIO = "lmstudio"
    LLAMACPP = "llamacpp"


class ModeType(str, Enum):
    """Available operation modes."""
    AUTONOMOUS = "autonomous"
    PENTESTER = "pentester"
    BLUE = "blue"
    OSINT = "osint"
    FORENSE = "forense"
    BUGBOUNTY = "bugbounty"
    REDTEAM = "redteam"
    VULNASSESSMENT = "vulnassessment"
    NETWORK = "network"
    WEBAPP = "webapp"
    SOCIAL = "social"
    DEVSECOPS = "devsecops"
    MALWARE = "malware"
    IOT = "iot"
    CLOUD = "cloud"
    MOBILE = "mobile"
    COMPLIANCE = "compliance"


@dataclass
class ScanResult:
    """Result of a security scan."""
    target: str
    scan_type: ScanType
    status: str
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    os_detection: Optional[str] = None
    raw_output: str = ""
    duration: float = 0.0
    errors: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """Security finding."""
    title: str
    description: str
    severity: SeverityLevel
    cvss: float = 0.0
    cve_id: Optional[str] = None
    affected_component: str = ""
    remediation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)


@dataclass
class Target:
    """Scan target."""
    value: str
    target_type: str  # ip, domain, url
    is_private: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    """Security report."""
    title: str
    target: Target
    scan_type: ScanType
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    timestamp: str = ""
    duration: float = 0.0
    raw_data: Dict[str, Any] = field(default_factory=dict)


class APIKeys(TypedDict, total=False):
    """API keys configuration."""
    shodan: str
    virustotal: str
    hunter: str
    censys: str
    securitytrails: str


@dataclass
class ToolConfig:
    """Tool configuration."""
    name: str
    command: str
    args: List[str] = field(default_factory=list)
    enabled: bool = True
    timeout: int = 30


@dataclass
class WorkflowStep:
    """Workflow step definition."""
    name: str
    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    on_success: Optional[str] = None
    on_failure: Optional[str] = None


@dataclass
class Workflow:
    """Workflow definition."""
    name: str
    description: str
    steps: List[WorkflowStep] = field(default_factory=list)
    requires_approval: bool = False


@dataclass
class AgentTask:
    """Agent task definition."""
    id: str
    description: str
    status: str = "pending"
    result: Optional[Any] = None
    error: Optional[str] = None
    tools_used: List[str] = field(default_factory=list)
    duration: float = 0.0


ToolResult = Union[str, Dict[str, Any], List[Any], None]
ToolExecutor = Callable[..., ToolResult]
ToolRegistry = Dict[str, ToolExecutor]
