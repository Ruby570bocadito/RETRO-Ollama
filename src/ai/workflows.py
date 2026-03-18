"""
Workflows System for RETRO-OLLAMA
Allows creating, saving, and executing custom workflows
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

BASE_DIR = Path(__file__).parent.parent.parent
WORKFLOWS_DIR = BASE_DIR / "workflows"
WORKFLOWS_FILE = BASE_DIR / "workflows.json"


class WorkflowCategory(Enum):
    """Workflow categories"""
    RECON = "recon"
    SCAN = "scan"
    VULN = "vuln"
    EXPLOIT = "exploit"
    POSTEXPLOIT = "postexploit"
    REPORT = "report"
    CUSTOM = "custom"


@dataclass
class WorkflowStep:
    """A single step in a workflow"""
    name: str
    tool: str
    args: str = ""
    description: str = ""
    condition: str = ""  # Optional condition to skip
    on_error: str = "continue"  # continue, stop, retry


@dataclass
class Workflow:
    """A complete workflow"""
    name: str
    description: str
    category: str
    steps: List[WorkflowStep]
    tags: List[str] = field(default_factory=list)
    author: str = "RETRO-OLLAMA"
    version: str = "1.0"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    modified_at: str = field(default_factory=lambda: datetime.now().isoformat())
    enabled: bool = True
    target_required: bool = True
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "steps": [asdict(s) for s in self.steps],
            "tags": self.tags,
            "author": self.author,
            "version": self.version,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "enabled": self.enabled,
            "target_required": self.target_required
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Workflow':
        """Create from dictionary"""
        steps = [WorkflowStep(**s) for s in data.get("steps", [])]
        return cls(
            name=data["name"],
            description=data["description"],
            category=data["category"],
            steps=steps,
            tags=data.get("tags", []),
            author=data.get("author", "RETRO-OLLAMA"),
            version=data.get("version", "1.0"),
            created_at=data.get("created_at", datetime.now().isoformat()),
            modified_at=data.get("modified_at", datetime.now().isoformat()),
            enabled=data.get("enabled", True),
            target_required=data.get("target_required", True)
        )


class WorkflowManager:
    """Manages workflows"""
    
    def __init__(self):
        self.workflows: Dict[str, Workflow] = {}
        self._load_builtin_workflows()
        self._load_custom_workflows()
    
    def _load_builtin_workflows(self):
        """Load built-in workflows"""
        builtin_workflows = [
            Workflow(
                name="recon",
                description="Complete reconnaissance workflow",
                category="recon",
                steps=[
                    WorkflowStep(name="Whois", tool="whois", description="Whois lookup"),
                    WorkflowStep(name="DNS", tool="dns_enum", description="DNS enumeration"),
                    WorkflowStep(name="Subdomains", tool="subdomain_enum", description="Subdomain enumeration"),
                    WorkflowStep(name="Port Scan", tool="quick_scan", description="Quick port scan"),
                    WorkflowStep(name="Shodan", tool="shodan_lookup", description="Shodan lookup"),
                ],
                tags=["recon", "passive", "active"]
            ),
            Workflow(
                name="quick_recon",
                description="Quick reconnaissance",
                category="recon",
                steps=[
                    WorkflowStep(name="Whois", tool="whois", description="Whois lookup"),
                    WorkflowStep(name="Quick Scan", tool="quick_scan", description="Quick port scan"),
                ],
                tags=["recon", "quick"]
            ),
            Workflow(
                name="vuln_assess",
                description="Vulnerability assessment",
                category="vuln",
                steps=[
                    WorkflowStep(name="Port Scan", tool="port_scan", description="Full port scan"),
                    WorkflowStep(name="Service Detect", tool="os_detect", description="OS detection"),
                    WorkflowStep(name="Vuln Scan", tool="vuln_scan", description="Vulnerability scan"),
                    WorkflowStep(name="Web Scan", tool="web_scan", description="Web vulnerability scan"),
                ],
                tags=["vulnerability", "assessment"]
            ),
            Workflow(
                name="web_assess",
                description="Web application assessment",
                category="vuln",
                steps=[
                    WorkflowStep(name="Tech Detect", tool="whatweb", description="Technology detection"),
                    WorkflowStep(name="Nikto", tool="nikto", description="Web vulnerability scan"),
                    WorkflowStep(name="Directory", tool="dir_scan", description="Directory enumeration"),
                    WorkflowStep(name="SSL Scan", tool="ssl_scan", description="SSL/TLS analysis"),
                ],
                tags=["web", "assessment"]
            ),
            Workflow(
                name="full_pentest",
                description="Full pentest (PTES)",
                category="exploit",
                steps=[
                    WorkflowStep(name="Recon", tool="workflow:recon", description="Reconnaissance phase"),
                    WorkflowStep(name="Port Scan", tool="full_scan", description="Full port scan"),
                    WorkflowStep(name="Vuln Scan", tool="vuln_scan", description="Vulnerability scan"),
                    WorkflowStep(name="Web Assess", tool="workflow:web_assess", description="Web assessment"),
                    WorkflowStep(name="Exploit Search", tool="search_exploits", description="Search exploits"),
                ],
                tags=["pentest", "full", "complete"]
            ),
            Workflow(
                name="stealth_scan",
                description="Evasion scan",
                category="scan",
                steps=[
                    WorkflowStep(name="Stealth Scan", tool="stealth_scan", description="Stealth nmap scan"),
                ],
                tags=["stealth", "evasion"]
            ),
            Workflow(
                name="osint",
                description="OSINT collection",
                category="recon",
                steps=[
                    WorkflowStep(name="Whois", tool="whois", description="Whois lookup"),
                    WorkflowStep(name="Shodan", tool="shodan_lookup", description="Shodan lookup"),
                    WorkflowStep(name="VirusTotal", tool="virustotal_scan", description="VirusTotal scan"),
                    WorkflowStep(name="Hunter", tool="hunter_lookup", description="Email hunting"),
                ],
                tags=["osint", "intel"]
            ),
        ]
        
        for wf in builtin_workflows:
            self.workflows[wf.name] = wf
    
    def _load_custom_workflows(self):
        """Load custom workflows from file"""
        if WORKFLOWS_FILE.exists():
            try:
                with open(WORKFLOWS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for wf_data in data.get("workflows", []):
                        wf = Workflow.from_dict(wf_data)
                        self.workflows[wf.name] = wf
            except Exception as e:
                print(f"Error loading workflows: {e}")
    
    def save_custom_workflows(self):
        """Save custom workflows to file"""
        custom_workflows = []
        for wf in self.workflows.values():
            if wf.author != "RETRO-OLLAMA":
                custom_workflows.append(wf.to_dict())
        
        with open(WORKFLOWS_FILE, "w", encoding="utf-8") as f:
            json.dump({"workflows": custom_workflows}, f, indent=2)
    
    def get_workflow(self, name: str) -> Optional[Workflow]:
        """Get workflow by name"""
        return self.workflows.get(name)
    
    def list_workflows(self) -> List[str]:
        """List all workflow names"""
        return list(self.workflows.keys())
    
    def list_by_category(self, category: str) -> List[Workflow]:
        """List workflows by category"""
        return [wf for wf in self.workflows.values() if wf.category == category]
    
    def add_workflow(self, workflow: Workflow) -> bool:
        """Add a new workflow"""
        if workflow.name in self.workflows:
            return False
        workflow.modified_at = datetime.now().isoformat()
        self.workflows[workflow.name] = workflow
        self.save_custom_workflows()
        return True
    
    def update_workflow(self, name: str, workflow: Workflow) -> bool:
        """Update existing workflow"""
        if name not in self.workflows:
            return False
        workflow.modified_at = datetime.now().isoformat()
        self.workflows[name] = workflow
        self.save_custom_workflows()
        return True
    
    def delete_workflow(self, name: str) -> bool:
        """Delete a workflow"""
        if name not in self.workflows:
            return False
        if self.workflows[name].author == "RETRO-OLLAMA":
            return False  # Can't delete built-in
        del self.workflows[name]
        self.save_custom_workflows()
        return True
    
    def get_workflow_details(self, name: str) -> Optional[Dict]:
        """Get workflow details"""
        wf = self.workflows.get(name)
        if wf:
            return wf.to_dict()
        return None


workflow_manager = WorkflowManager()


def get_workflow_manager() -> WorkflowManager:
    """Get global workflow manager"""
    return workflow_manager


def list_all_workflows() -> List[Dict]:
    """List all workflows with details"""
    return [wf.to_dict() for wf in workflow_manager.workflows.values()]


def create_workflow(name: str, description: str, category: str, steps: List[Dict], 
                   tags: List[str] = None, target_required: bool = True) -> bool:
    """Create a new custom workflow"""
    wf_steps = [WorkflowStep(**s) for s in steps]
    workflow = Workflow(
        name=name,
        description=description,
        category=category,
        steps=wf_steps,
        tags=tags or [],
        author="user",
        target_required=target_required
    )
    return workflow_manager.add_workflow(workflow)
