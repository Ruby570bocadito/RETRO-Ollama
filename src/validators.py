"""Input validation schemas for RETRO-Ollama."""

import re
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


class IPAddress(BaseModel):
    """IP address validation."""
    value: str
    
    @field_validator("value")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v
    
    def is_private(self) -> bool:
        """Check if IP is private."""
        ip = ip_address(self.value)
        return ip.is_private
    
    def is_loopback(self) -> bool:
        """Check if IP is loopback."""
        ip = ip_address(self.value)
        return ip.is_loopback


class Domain(BaseModel):
    """Domain validation."""
    value: str
    
    @field_validator("value")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError(f"Invalid domain: {v}")
        return v.lower()


class URL(BaseModel):
    """URL validation."""
    value: str
    
    @field_validator("value")
    @classmethod
    def validate_url(cls, v: str) -> str:
        try:
            result = urlparse(v)
            if not all([result.scheme, result.netloc]):
                raise ValueError()
        except ValueError:
            raise ValueError(f"Invalid URL: {v}")
        return v
    
    def get_domain(self) -> str:
        """Get domain from URL."""
        return urlparse(self.value).netloc
    
    def get_scheme(self) -> str:
        """Get scheme from URL."""
        return urlparse(self.value).scheme


class ScanRequest(BaseModel):
    """Scan request validation."""
    target: str = Field(..., description="Target to scan (IP, domain, or URL)")
    scan_type: str = Field(default="quick", description="Type of scan")
    ports: Optional[str] = Field(default=None, description="Ports to scan")
    stealth: bool = Field(default=False, description="Use stealth mode")
    
    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        valid_types = ["quick", "full", "vuln", "web", "dir", "stealth", "os"]
        if v not in valid_types:
            raise ValueError(f"Invalid scan type. Must be one of: {valid_types}")
        return v
    
    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        if re.match(ip_pattern, v):
            try:
                ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid IP address: {v}")
        elif not re.match(domain_pattern, v):
            try:
                result = urlparse(v)
                if not all([result.scheme, result.netloc]):
                    raise ValueError(f"Invalid target: {v}")
            except Exception:
                raise ValueError(f"Invalid target: {v}")
        
        return v


class CVERequest(BaseModel):
    """CVE search request."""
    cve_id: Optional[str] = Field(default=None, description="CVE ID (e.g., CVE-2021-44228)")
    keyword: Optional[str] = Field(default=None, description="Search keyword")
    
    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        pattern = r'^CVE-\d{4}-\d{4,}$'
        if not re.match(pattern, v, re.IGNORECASE):
            raise ValueError("Invalid CVE ID format. Expected: CVE-YYYY-NNNN")
        return v.upper()


class APIKeyRequest(BaseModel):
    """API key validation."""
    service: str = Field(..., description="Service name")
    key: str = Field(..., description="API key")
    
    @field_validator("service")
    @classmethod
    def validate_service(cls, v: str) -> str:
        valid_services = ["shodan", "virustotal", "hunter", "censys", "securitytrails"]
        if v.lower() not in valid_services:
            raise ValueError(f"Invalid service. Must be one of: {valid_services}")
        return v.lower()
    
    @field_validator("key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("API key too short")
        return v.strip()


class ReportRequest(BaseModel):
    """Report generation request."""
    title: str = Field(..., min_length=1, max_length=200)
    target: str = Field(..., description="Target for the report")
    format: str = Field(default="json", description="Report format")
    include_raw: bool = Field(default=False, description="Include raw data")
    
    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        valid_formats = ["json", "html", "markdown", "pdf"]
        if v.lower() not in valid_formats:
            raise ValueError(f"Invalid format. Must be one of: {valid_formats}")
        return v.lower()


class WorkflowRequest(BaseModel):
    """Workflow execution request."""
    workflow_name: str = Field(..., description="Name of workflow to execute")
    target: str = Field(..., description="Target for workflow")
    params: dict = Field(default_factory=dict, description="Additional parameters")
    
    @field_validator("workflow_name")
    @classmethod
    def validate_workflow_name(cls, v: str) -> str:
        valid_workflows = [
            "recon", "quick_recon", "vuln_assess", 
            "web_assess", "full_pentest", "stealth_scan", "osint"
        ]
        if v not in valid_workflows:
            raise ValueError(f"Invalid workflow. Must be one of: {valid_workflows}")
        return v


def validate_target(target: str) -> tuple[str, str]:
    """Validate and identify target type.
    
    Returns:
        tuple: (target_type, validated_target)
        target_type: 'ip', 'domain', or 'url'
    """
    target = target.strip()
    
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, target):
        try:
            ip_address(target)
            return ("ip", target)
        except ValueError:
            pass
    
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, target):
        return ("domain", target.lower())
    
    try:
        result = urlparse(target)
        if all([result.scheme, result.netloc]):
            return ("url", target)
    except Exception:
        pass
    
    raise ValueError(f"Invalid target: {target}")
