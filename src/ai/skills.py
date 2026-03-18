"""
Skills System for RETRO-OLLAMA
Allows loading and executing custom skills/plugins
"""

import json
import os
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
SKILLS_DIR = BASE_DIR / "skills"


@dataclass
class Skill:
    """Represents a skill/plugin"""
    name: str
    description: str
    category: str
    commands: List[str]
    func: Optional[Callable] = None
    file_path: Optional[str] = None
    enabled: bool = True
    version: str = "1.0"
    author: str = "Unknown"
    tags: List[str] = field(default_factory=list)
    
    def execute(self, *args, **kwargs) -> Any:
        """Execute the skill function"""
        if self.func:
            return self.func(*args, **kwargs)
        return {"error": "No function defined"}


class SkillRegistry:
    """Registry of available skills"""
    
    def __init__(self):
        self.skills: Dict[str, Skill] = {}
        self.categories: Dict[str, List[str]] = {}
        self._load_builtin_skills()
    
    def _load_builtin_skills(self):
        """Load built-in skills"""
        builtin_skills = [
            Skill(
                name="network_scan",
                description="Advanced network scanning with Nmap",
                category="scanning",
                commands=["/scan", "/nmap", "/network"],
                tags=["nmap", "scanning", "network"]
            ),
            Skill(
                name="web_enum",
                description="Web enumeration and directory busting",
                category="enumeration",
                commands=["/dir", "/enumweb", "/webenum"],
                tags=["web", "directories", "gobuster"]
            ),
            Skill(
                name="vuln_detect",
                description="Vulnerability detection and assessment",
                category="vulnerability",
                commands=["/vuln", "/detect", "/cve"],
                tags=["vulnerability", "cve", "nuclei"]
            ),
            Skill(
                name="osint_collect",
                description="OSINT collection and reconnaissance",
                category="osint",
                commands=["/osint", "/recon", "/intel"],
                tags=["osint", "reconnaissance", "whois"]
            ),
            Skill(
                name="exploit_search",
                description="Search and download exploits",
                category="exploitation",
                commands=["/exploit", "/searchsploit", "/pwn"],
                tags=["exploit", "metasploit", "searchsploit"]
            ),
            Skill(
                name="code_gen",
                description="Generate security code and payloads",
                category="generation",
                commands=["/code", "/shell", "/payload"],
                tags=["code", "payload", "shell"]
            ),
            Skill(
                name="report_gen",
                description="Generate pentest reports",
                category="reporting",
                commands=["/report", "/summary", "/export"],
                tags=["report", "markdown", "html"]
            ),
            Skill(
                name="cloud_audit",
                description="Cloud security auditing (AWS/Azure/GCP)",
                category="cloud",
                commands=["/cloud", "/aws", "/azure"],
                tags=["cloud", "aws", "azure", "gcp"]
            ),
            Skill(
                name="mobile_audit",
                description="Mobile app security auditing",
                category="mobile",
                commands=["/mobile", "/apk", "/ipa"],
                tags=["mobile", "android", "ios", "apk"]
            ),
            Skill(
                name="malware_analysis",
                description="Malware analysis and reverse engineering",
                category="malware",
                commands=["/malware", "/analyze", "/reverse"],
                tags=["malware", "analysis", "reverse"]
            ),
        ]
        
        for skill in builtin_skills:
            self.register(skill)
    
    def register(self, skill: Skill):
        """Register a new skill"""
        self.skills[skill.name] = skill
        
        if skill.category not in self.categories:
            self.categories[skill.category] = []
        self.categories[skill.category].append(skill.name)
    
    def get_skill(self, name: str) -> Optional[Skill]:
        """Get skill by name"""
        return self.skills.get(name)
    
    def get_by_command(self, command: str) -> Optional[Skill]:
        """Get skill by command"""
        for skill in self.skills.values():
            if command in skill.commands:
                return skill
        return None
    
    def get_by_category(self, category: str) -> List[Skill]:
        """Get all skills in a category"""
        skill_names = self.categories.get(category, [])
        return [self.skills[name] for name in skill_names]
    
    def list_skills(self) -> Dict[str, Skill]:
        """List all skills"""
        return self.skills
    
    def list_categories(self) -> List[str]:
        """List all categories"""
        return list(self.categories.keys())
    
    def enable(self, name: str) -> bool:
        """Enable a skill"""
        skill = self.skills.get(name)
        if skill:
            skill.enabled = True
            return True
        return False
    
    def disable(self, name: str) -> bool:
        """Disable a skill"""
        skill = self.skills.get(name)
        if skill:
            skill.enabled = False
            return True
        return False


skill_registry = SkillRegistry()


def get_skill_registry() -> SkillRegistry:
    """Get the global skill registry"""
    return skill_registry


def list_all_skills() -> List[Dict]:
    """List all skills with details"""
    skills = []
    for skill in skill_registry.skills.values():
        skills.append({
            "name": skill.name,
            "description": skill.description,
            "category": skill.category,
            "commands": skill.commands,
            "enabled": skill.enabled,
            "version": skill.version,
            "author": skill.author,
            "tags": skill.tags
        })
    return skills


def get_skill_by_command(command: str) -> Optional[Skill]:
    """Get skill that handles a command"""
    return skill_registry.get_by_command(command)


def get_skills_by_category(category: str) -> List[Skill]:
    """Get skills by category"""
    return skill_registry.get_by_category(category)
