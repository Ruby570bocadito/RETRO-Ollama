"""
PTAI Agent - Autonomous Pentesting AI Agent
Enhanced with reasoning, workflows, memory, learning, and parallel execution
"""

import json
import re
import hashlib
import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
import queue

class AgentState(Enum):
    """Agent execution states"""
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    WAITING = "waiting"
    RETRYING = "retrying"
    PARALLEL = "parallel"
    DONE = "done"
    ERROR = "error"

class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class AgentThought:
    """Represents a thought in the agent's reasoning chain"""
    step: int
    thought: str
    action: str
    target: Optional[str] = None
    tools: List[str] = field(default_factory=list)
    result: Optional[str] = None
    confidence: float = 0.5
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class AgentPlan:
    """Represents a plan to achieve a goal"""
    goal: str
    steps: List[AgentThought] = field(default_factory=list)
    current_step: int = 0
    completed: bool = False
    iterations: int = 0

@dataclass
class Finding:
    """Represents a security finding"""
    target: str
    severity: str
    title: str
    description: str
    tool: str
    evidence: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    cve: str = ""
    cvss: float = 0.0

@dataclass
class CacheEntry:
    """Cached result"""
    key: str
    value: Any
    timestamp: datetime
    ttl: int = 3600
    
    def is_valid(self) -> bool:
        return datetime.now() - self.timestamp < timedelta(seconds=self.ttl)

class ResultCache:
    """Cache for tool results"""
    
    def __init__(self, max_size: int = 100, default_ttl: int = 3600):
        self.cache: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.hits = 0
        self.misses = 0
    
    def _make_key(self, tool: str, *args, **kwargs) -> str:
        """Generate cache key"""
        data = f"{tool}:{args}:{kwargs}"
        return hashlib.md5(data.encode()).hexdigest()
    
    def get(self, tool: str, *args, **kwargs) -> Optional[Any]:
        """Get cached result"""
        key = self._make_key(tool, *args, **kwargs)
        entry = self.cache.get(key)
        
        if entry and entry.is_valid():
            self.hits += 1
            return entry.value
        
        self.misses += 1
        return None
    
    def set(self, value: Any, tool: str = None, *args, ttl: int = None, **kwargs):
        """Set cached result"""
        key = self._make_key(tool or "default", *args, **kwargs)
        
        # Evict oldest if full
        if len(self.cache) >= self.max_size:
            oldest = min(self.cache.items(), key=lambda x: x[1].timestamp)
            del self.cache[oldest[0]]
        
        self.cache[key] = CacheEntry(
            key=key,
            value=value,
            timestamp=datetime.now(),
            ttl=ttl or self.default_ttl
        )
    
    def invalidate(self, tool: str = None):
        """Invalidate cache"""
        if tool:
            # Remove entries for specific tool
            keys = [k for k, v in self.cache.items() if tool in k]
            for k in keys:
                del self.cache[k]
        else:
            self.cache.clear()
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{hit_rate:.2%}"
        }

class AgentSession:
    """Manages agent sessions"""
    
    def __init__(self, session_id: str = None):
        self.id = session_id or hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.data: Dict[str, Any] = {}
        self.history: List[Dict] = []
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now()
    
    def add_history(self, action: str, result: Any):
        """Add to session history"""
        self.history.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "result": str(result)[:200]
        })
        self.update_activity()
    
    def is_expired(self, timeout_minutes: int = 30) -> bool:
        """Check if session is expired"""
        return datetime.now() - self.last_activity > timedelta(minutes=timeout_minutes)

class SessionManager:
    """Manages multiple agent sessions"""
    
    def __init__(self, max_sessions: int = 10):
        self.sessions: Dict[str, AgentSession] = {}
        self.max_sessions = max_sessions
        self.current_session: Optional[AgentSession] = None
    
    def create_session(self, session_id: str = None) -> AgentSession:
        """Create new session"""
        # Clean expired sessions
        self._clean_expired()
        
        if len(self.sessions) >= self.max_sessions:
            # Remove oldest
            oldest = min(self.sessions.items(), key=lambda x: x[1].created_at)
            del self.sessions[oldest[0]]
        
        session = AgentSession(session_id)
        self.sessions[session.id] = session
        self.current_session = session
        return session
    
    def get_session(self, session_id: str) -> Optional[AgentSession]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def set_current(self, session_id: str) -> bool:
        """Set current session"""
        session = self.sessions.get(session_id)
        if session:
            self.current_session = session
            return True
        return False
    
    def _clean_expired(self):
        """Remove expired sessions"""
        expired = [k for k, v in self.sessions.items() if v.is_expired()]
        for k in expired:
            del self.sessions[k]
    
    def list_sessions(self) -> List[Dict]:
        """List all sessions"""
        return [
            {
                "id": s.id,
                "created": s.created_at.isoformat(),
                "last_activity": s.last_activity.isoformat(),
                "history_count": len(s.history)
            }
            for s in self.sessions.values()
        ]

class AgentConfig:
    """Agent configuration"""
    
    def __init__(self):
        self.max_iterations = 10
        self.timeout = 300
        self.retry_count = 3
        self.retry_delay = 2
        self.confidence_threshold = 0.7
        self.parallel_tools = True
        self.max_parallel = 3
        self.cache_enabled = True
        self.cache_ttl = 3600
        self.learning_enabled = True
        self.auto_select_tools = True
        self.ask_confirmation = False
    
    def to_dict(self) -> Dict:
        return {
            "max_iterations": self.max_iterations,
            "timeout": self.timeout,
            "retry_count": self.retry_count,
            "confidence_threshold": self.confidence_threshold,
            "parallel_tools": self.parallel_tools,
            "max_parallel": self.max_parallel,
            "cache_enabled": self.cache_enabled,
            "learning_enabled": self.learning_enabled
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'AgentConfig':
        config = cls()
        for k, v in data.items():
            if hasattr(config, k):
                setattr(config, k, v)
        return config

class ParallelExecutor:
    """Execute tools in parallel"""
    
    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self.results: Dict[str, Any] = {}
        self.errors: Dict[str, str] = {}
    
    def execute_parallel(self, tasks: List[Dict]) -> Dict[str, Any]:
        """Execute multiple tools in parallel"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {
                executor.submit(self._execute_task, task): task
                for task in tasks
            }
            
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                try:
                    result = future.result()
                    results[task['name']] = result
                except Exception as e:
                    results[task['name']] = {"error": str(e)}
        
        return results
    
    def _execute_task(self, task: Dict) -> Any:
        """Execute single task"""
        tool = task.get('tool')
        func = task.get('func')
        args = task.get('args', [])
        kwargs = task.get('kwargs', {})
        
        if func:
            return func(*args, **kwargs)
        return {"error": "No function provided"}

class LearningEngine:
    """Agent learning from feedback"""
    
    def __init__(self):
        self.feedback_history: List[Dict] = []
        self.tool_preferences: Dict[str, Dict] = {}
        self.patterns: Dict[str, Any] = {}
    
    def add_feedback(self, action: str, result: Any, rating: int, comment: str = ""):
        """Add user feedback"""
        self.feedback_history.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "result": str(result)[:500],
            "rating": rating,  # 1-5
            "comment": comment
        })
        
        # Update tool preferences
        if rating >= 4:
            self._learn_success(action)
        elif rating <= 2:
            self._learn_failure(action)
    
    def _learn_success(self, action: str):
        """Learn from successful action"""
        if action not in self.tool_preferences:
            self.tool_preferences[action] = {"success": 0, "total": 0}
        self.tool_preferences[action]["success"] += 1
        self.tool_preferences[action]["total"] += 1
    
    def _learn_failure(self, action: str):
        """Learn from failed action"""
        if action not in self.tool_preferences:
            self.tool_preferences[action] = {"success": 0, "total": 0}
        self.tool_preferences[action]["total"] += 1
    
    def get_recommendation(self, context: Dict) -> Optional[str]:
        """Get tool recommendation based on learning"""
        action = context.get('action')
        
        if action in self.tool_preferences:
            prefs = self.tool_preferences[action]
            success_rate = prefs["success"] / prefs["total"] if prefs["total"] > 0 else 0
            
            if success_rate >= 0.7:
                return f"High success rate ({success_rate:.0%}) for {action}"
            elif success_rate <= 0.3:
                return f"Low success rate ({success_rate:.0%}) for {action}"
        
        return None
    
    def get_stats(self) -> Dict:
        """Get learning statistics"""
        return {
            "feedback_count": len(self.feedback_history),
            "tool_preferences": self.tool_preferences,
            "patterns": len(self.patterns)
        }

@dataclass
class AgentMemory:
    """Agent memory for context retention"""
    recent_findings: List[Finding] = field(default_factory=list)
    scan_history: List[Dict] = field(default_factory=list)
    vulnerabilities_found: List[Dict] = field(default_factory=list)
    targets_scanned: List[str] = field(default_factory=list)
    successful_tools: Dict[str, int] = field(default_factory=dict)
    failed_tools: Dict[str, int] = field(default_factory=dict)
    conversation_history: List[Dict] = field(default_factory=list)
    
    def add_finding(self, finding: Finding):
        self.recent_findings.append(finding)
        if len(self.recent_findings) > 20:
            self.recent_findings = self.recent_findings[-20:]
    
    def add_vulnerability(self, vuln: Dict):
        self.vulnerabilities_found.append(vuln)
    
    def record_success(self, tool_name: str):
        self.successful_tools[tool_name] = self.successful_tools.get(tool_name, 0) + 1
    
    def record_failure(self, tool_name: str):
        self.failed_tools[tool_name] = self.failed_tools.get(tool_name, 0) + 1
    
    def get_best_tool(self, category: str) -> Optional[str]:
        """Get the most successful tool for a category"""
        if category in self.successful_tools:
            return max(self.successful_tools.keys(), 
                      key=lambda k: self.successful_tools[k])
        return None
    
    def get_context(self) -> str:
        """Get formatted context for LLM"""
        context = []
        
        # Recent findings
        if self.recent_findings:
            context.append(f"=== HALLAZGOS RECIENTES ({len(self.recent_findings)}) ===")
            for f in self.recent_findings[-5:]:
                context.append(f"  [{f.severity.upper()}] {f.title}")
        
        # Vulnerabilities
        if self.vulnerabilities_found:
            context.append(f"\n=== VULNERABILIDADES ({len(self.vulnerabilities_found)}) ===")
            for v in self.vulnerabilities_found[-5:]:
                context.append(f"  - {v.get('name', 'Unknown')} ({v.get('severity', '?')})")
        
        # Targets scanned
        if self.targets_scanned:
            context.append(f"\n=== TARGETS ESCANEADOS ===")
            context.append(f"  {', '.join(self.targets_scanned[-5:])}")
        
        # Tool success rate
        if self.successful_tools:
            context.append(f"\n=== HERRAMIENTAS EXITOSAS ===")
            for tool, count in sorted(self.successful_tools.items(), 
                                      key=lambda x: x[1], reverse=True)[:3]:
                context.append(f"  {tool}: {count} usos")
        
        return "\n".join(context) if context else "Sin contexto previo"
    
    def add_message(self, role: str, content: str):
        """Add to conversation history"""
        self.conversation_history.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
        # Keep last 20 messages
        if len(self.conversation_history) > 20:
            self.conversation_history = self.conversation_history[-20:]

class AgentTool:
    """Represents a tool the agent can use"""
    def __init__(self, name: str, description: str, func: Callable, 
                 categories: List[str], timeout: int = 30, 
                 fallback: Optional[str] = None):
        self.name = name
        self.description = description
        self.func = func
        self.categories = categories
        self.timeout = timeout
        self.fallback = fallback
        self.usage_count = 0
        self.success_count = 0
        self.fail_count = 0
    
    def execute(self, *args, **kwargs) -> Any:
        """Execute the tool with error handling"""
        self.usage_count += 1
        try:
            start = time.time()
            result = self.func(*args, **kwargs)
            elapsed = time.time() - start
            
            if elapsed > self.timeout:
                self.fail_count += 1
                return {"error": f"Timeout ({self.timeout}s)", "tool": self.name}
            
            self.success_count += 1
            return result
        except Exception as e:
            self.fail_count += 1
            return {"error": str(e), "tool": self.name}
    
    def get_success_rate(self) -> float:
        if self.usage_count == 0:
            return 0.0
        return self.success_count / self.usage_count

class ToolRegistry:
    """Registry of available tools for the agent"""
    
    def __init__(self):
        self.tools: Dict[str, AgentTool] = {}
        self._register_default_tools()
    
    def _register_default_tools(self):
        """Register default pentesting tools with fallbacks"""
        from src.tools.pentest import quick_scan, vuln_scan, web_scan, full_scan, stealth_scan, network_discovery
        from src.tools.system import execute_command
        from src.tools.apis import shodan_scan, virustotal_scan, whois_lookup
        
        tools = [
            AgentTool("quick_scan", "Escaneo rápido de puertos", quick_scan, 
                     ["scan", "recon"], timeout=60, fallback="stealth_scan"),
            AgentTool("network_discovery", "Descubrimiento de hosts en red", network_discovery, 
                     ["scan", "recon", "network"], timeout=60),
            AgentTool("vuln_scan", "Detección de vulnerabilidades", vuln_scan, 
                     ["scan", "vuln"], timeout=120, fallback="quick_scan"),
            AgentTool("web_scan", "Análisis de aplicaciones web", web_scan, 
                     ["scan", "web"], timeout=90, fallback="vuln_scan"),
            AgentTool("full_scan", "Escaneo completo", full_scan, 
                     ["scan", "full"], timeout=300, fallback="vuln_scan"),
            AgentTool("stealth_scan", "Escaneo sigiloso/evasión", stealth_scan, 
                     ["scan", "stealth"], timeout=120, fallback="quick_scan"),
            AgentTool("execute_command", "Ejecutar comando del sistema", execute_command, 
                     ["system"], timeout=30),
            AgentTool("shodan_lookup", "Consulta Shodan", shodan_scan, 
                     ["osint"], timeout=15),
            AgentTool("virus_total_scan", "Escaneo VirusTotal", virustotal_scan, 
                     ["osint"], timeout=20),
            AgentTool("whois_lookup", "Whois lookup", whois_lookup, 
                     ["osint"], timeout=10),
        ]
        
        for tool in tools:
            self.tools[tool.name] = tool
    
    def register(self, tool: AgentTool):
        """Register a new tool"""
        self.tools[tool.name] = tool
    
    def get_tool(self, name: str) -> Optional[AgentTool]:
        """Get tool by name"""
        return self.tools.get(name)
    
    def get_tool_with_fallback(self, name: str) -> Optional[AgentTool]:
        """Get tool, try fallback if not available"""
        tool = self.tools.get(name)
        if tool:
            return tool
        if tool and tool.fallback:
            return self.tools.get(tool.fallback)
        return None
    
    def get_tools_by_category(self, category: str) -> List[AgentTool]:
        """Get tools by category"""
        return [t for t in self.tools.values() if category in t.categories]
    
    def get_best_tool(self, category: str, success_history: Dict[str, int]) -> Optional[AgentTool]:
        """Get best tool for category based on success history"""
        tools = self.get_tools_by_category(category)
        if not tools:
            return None
        
        # If we have history, prefer successful tools
        if success_history:
            for tool_name in sorted(success_history.keys(), 
                                   key=lambda k: success_history[k], 
                                   reverse=True):
                for tool in tools:
                    if tool.name == tool_name:
                        return tool
        
        # Otherwise, return first available
        return tools[0]
    
    def list_tools(self) -> List[str]:
        """List all tool names"""
        return list(self.tools.keys())
    
    def get_tool_info(self) -> List[Dict]:
        """Get info about all tools"""
        return [
            {
                "name": t.name,
                "description": t.description,
                "categories": t.categories,
                "usage_count": t.usage_count,
                "success_rate": t.get_success_rate(),
                "fallback": t.fallback
            }
            for t in self.tools.values()
        ]

class AgentWorkflow:
    """Autonomous workflow execution engine"""
    
    WORKFLOWS = {
        "recon": {
            "name": "Intelligence Reconnaissance",
            "description": "Recolección completa de información",
            "steps": [
                {"action": "whois_lookup", "description": "Información Whois", "tool": "whois_lookup"},
                {"action": "subdomain_enum", "description": "Enumeración de subdominios", "tool": "execute_command"},
                {"action": "port_scan", "description": "Escaneo de puertos", "tool": "quick_scan"},
                {"action": "service_detection", "description": "Detección de servicios", "tool": "quick_scan"},
                {"action": "osint_passive", "description": "OSINT pasivo", "tool": "shodan_lookup"},
            ]
        },
        "vuln_assess": {
            "name": "Vulnerability Assessment",
            "description": "Evaluación de vulnerabilidades",
            "steps": [
                {"action": "quick_scan", "description": "Escaneo rápido de puertos", "tool": "quick_scan"},
                {"action": "service_identify", "description": "Identificar servicios", "tool": "quick_scan"},
                {"action": "vuln_scan", "description": "Escaneo de vulnerabilidades", "tool": "vuln_scan"},
                {"action": "web_scan", "description": "Análisis web", "tool": "web_scan"},
                {"action": "analyze_findings", "description": "Analizar hallazgos", "tool": None},
            ]
        },
        "web_assess": {
            "name": "Web Application Assessment",
            "description": "Evaluación completa de aplicación web",
            "steps": [
                {"action": "tech_detection", "description": "Detección de tecnologías", "tool": "web_scan"},
                {"action": "dir_scan", "description": "Enumeración de directorios", "tool": "execute_command"},
                {"action": "vuln_scan", "description": "Vulnerabilidades web", "tool": "vuln_scan"},
                {"action": "xss_test", "description": "Pruebas XSS", "tool": "vuln_scan"},
                {"action": "sql_test", "description": "Pruebas SQLi", "tool": "vuln_scan"},
            ]
        },
        "full_pentest": {
            "name": "Full Pentest",
            "description": "Pentest completo PTES",
            "steps": [
                {"action": "recon", "description": "Fase de reconocimiento", "tool": "recon"},
                {"action": "enum", "description": "Fase de enumeración", "tool": "quick_scan"},
                {"action": "vuln_scan", "description": "Evaluación de vulnerabilidades", "tool": "vuln_scan"},
                {"action": "exploit", "description": "Fase de explotación", "tool": "execute_command"},
                {"action": "report", "description": "Generación de reporte", "tool": None},
            ]
        },
        "quick_recon": {
            "name": "Quick Recon",
            "description": "Reconocimiento rápido",
            "steps": [
                {"action": "whois", "description": "Whois", "tool": "whois_lookup"},
                {"action": "quick_scan", "description": "Port scan", "tool": "quick_scan"},
                {"action": "shodan", "description": "Shodan", "tool": "shodan_lookup"},
            ]
        }
    }
    
    @classmethod
    def get_workflow(cls, name: str) -> Optional[Dict]:
        return cls.WORKFLOWS.get(name.lower())
    
    @classmethod
    def list_workflows(cls) -> List[str]:
        return list(cls.WORKFLOWS.keys())

class ReasoningEngine:
    """Enhanced reasoning and thought process with chain-of-thought"""
    
    def __init__(self):
        self.thought_history: List[AgentThought] = []
        self.current_plan: Optional[AgentPlan] = None
        self.confidence_threshold = 0.7
    
    def _get_local_network(self) -> str:
        """Detect local network range for network discovery"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.rsplit('.', 1)
            if len(parts) == 2:
                return f"{parts[0]}.0/24"
        except Exception:
            pass
        return "192.168.1.0/24"
    
    def think(self, user_input: str, context: Dict) -> str:
        """Process user input and generate reasoning with chain-of-thought"""
        thoughts = []
        
        # Analyze input
        intent = self._analyze_intent(user_input)
        
        # Generate thought chain (Chain-of-Thought)
        thoughts.append(f"[1/4] ANALYZING: {user_input}")
        thoughts.append(f"    Intent detected: {intent.get('action', 'unknown')}")
        
        if intent.get('target'):
            thoughts.append(f"    Target: {intent['target']}")
        
        # Determine necessary tools
        tools = self._select_tools(intent)
        if tools:
            thoughts.append(f"[2/4] TOOLS SELECTED: {', '.join(tools)}")
        
        # Plan execution with confidence
        plan = self._create_plan(intent, context)
        if plan:
            thoughts.append(f"[3/4] PLANNING: {len(plan.steps)} steps identified")
            for i, step in enumerate(plan.steps, 1):
                thoughts.append(f"    Step {i}: {step.action}")
        
        thoughts.append(f"[4/4] READY TO EXECUTE")
        
        return "\n".join(thoughts)
    
    def think_step_by_step(self, action: str, result: Any, next_actions: List[str]) -> str:
        """Generate thought for next step based on results"""
        thought = f"[LOOP] Action: {action}\n"
        thought += f"    Result: {str(result)[:200]}...\n"
        
        if next_actions:
            thought += f"    Next: {' -> '.join(next_actions[:3])}"
        
        return thought
    
    def evaluate_result(self, result: Any) -> Dict:
        """Evaluate execution result and determine next steps"""
        evaluation = {
            "success": True,
            "findings": [],
            "next_actions": [],
            "confidence": 0.5
        }
        
        if isinstance(result, dict):
            if "error" in result:
                evaluation["success"] = False
                evaluation["next_actions"] = ["retry", "alternative"]
            
            # Check for vulnerabilities
            output = result.get("output", "")
            if "vuln" in output.lower() or "critical" in output.lower():
                evaluation["findings"].append("potential_vulnerability")
                evaluation["confidence"] = 0.8
            
            if "open" in output.lower() or "port" in output.lower():
                evaluation["findings"].append("ports_found")
                evaluation["next_actions"] = ["service_scan", "vuln_scan"]
        
        return evaluation
    
    def _analyze_intent(self, text: str) -> Dict:
        """Analyze user intent from text with NLP"""
        text_lower = text.lower()
        
        intent = {"action": "general", "target": None, "tools": [], "urgency": "normal", "workflow": None}
        
        # Attack vectors
        if any(w in text_lower for w in ['attack', 'exploit', 'hack', 'compromised', 'breach', 'penetra']):
            intent['action'] = "attack"
            intent['urgency'] = "high"
            intent['workflow'] = "full_pentest"
        
        # Scanning
        elif any(w in text_lower for w in ['scan', 'escanea', 'analiza', 'check', 'test']):
            intent['action'] = "scan"
            if 'vuln' in text_lower or 'vulnerab' in text_lower:
                intent['action'] = "vuln_scan"
                intent['workflow'] = "vuln_assess"
            elif 'web' in text_lower or 'http' in text_lower or 'sitio' in text_lower:
                intent['action'] = "web_scan"
                intent['workflow'] = "web_assess"
            elif 'full' in text_lower or 'completo' in text_lower:
                intent['action'] = "full_scan"
                intent['workflow'] = "full_pentest"
            elif 'quick' in text_lower or 'rapido' in text_lower:
                intent['action'] = "quick_scan"
                intent['workflow'] = "quick_recon"
        
        # Reconnaissance
        elif any(w in text_lower for w in ['recon', 'intel', 'investiga', 'busca info', 'reconocimiento']):
            intent['action'] = "recon"
            intent['workflow'] = "recon"
        
        # Full pentest
        elif any(w in text_lower for w in ['pentest', 'full test', 'auditoria']):
            intent['action'] = "pentest"
            intent['workflow'] = "full_pentest"
        
        # Code generation
        elif any(w in text_lower for w in ['genera', 'create', 'make', 'script', 'code', 'crea']):
            intent['action'] = "generate"
        
        # Code improvement / enhancement
        elif any(w in text_lower for w in [
            'mejora', 'improve', 'optimiza', 'optimize', 'refactoriza', 'refactor',
            'amplia', 'expande', 'enhance', 'mejoralo', 'mejorar', 'corrige', 'fix',
            'aggiunta', 'add', 'agrego', 'modifica', 'modify', 'actualiza', 'update'
        ]):
            intent['action'] = "improve_code"
        
        # Research / search / investigate
        elif any(w in text_lower for w in [
            'busca', 'search', 'investiga', 'research', 'como', 'how',
            'que es', 'what is', 'explica', 'explain', 'dime', 'tell me',
            'encontrar', 'find', 'solucion', 'solution', 'problema', 'problem',
            'error', 'fix', 'resolver', 'resolve', 'ayuda', 'help',
            'documentacion', 'docs', 'manual', 'tutorial', 'guia', 'guide'
        ]):
            intent['action'] = "research"
        
        # Analysis
        elif any(w in text_lower for w in ['analiza', 'analyze', 'evalua', 'review', 'resultados']):
            intent['action'] = "analyze"
        
        # OSINT
        elif any(w in text_lower for w in ['whois', 'shodan', 'hunter', 'osint']):
            intent['action'] = "osint"
        
        # Network discovery / devices on network
        elif any(w in text_lower for w in [
            'dispositivos', 'devices', 'hosts', 'equipos',
            'mi red', 'my network', 'local network', 'la red',
            'encuentra', 'find', 'detect', 'descubre',
            'arp scan', 'network scan', 'escaneo red'
        ]):
            intent['action'] = "network_discovery"
            intent['workflow'] = "quick_recon"
            intent['target'] = self._get_local_network()
        
        # Extract target
        target = self._extract_target(text)
        if target:
            intent['target'] = target
        
        return intent
    
    def _extract_target(self, text: str) -> Optional[str]:
        """Extract IP, domain, or URL from text"""
        # IP pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, text)
        if ip_match:
            return ip_match.group()
        
        # Domain pattern
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domain_match = re.search(domain_pattern, text)
        if domain_match:
            return domain_match.group()
        
        return None
    
    def _select_tools(self, intent: Dict) -> List[str]:
        """Select appropriate tools based on intent"""
        action = intent.get('action', '')
        
        tool_mapping = {
            'scan': ['quick_scan'],
            'vuln_scan': ['quick_scan', 'vuln_scan'],
            'web_scan': ['web_scan'],
            'full_scan': ['full_scan'],
            'quick_scan': ['quick_scan'],
            'recon': ['whois_lookup', 'shodan_lookup', 'quick_scan'],
            'attack': ['quick_scan', 'vuln_scan', 'execute_command'],
            'generate': [],
            'analyze': [],
            'osint': ['whois_lookup', 'shodan_lookup'],
            'pentest': ['quick_scan', 'vuln_scan', 'web_scan', 'full_scan'],
        }
        
        return tool_mapping.get(action, [])
    
    def _create_plan(self, intent: Dict, context: Dict) -> Optional[AgentPlan]:
        """Create execution plan based on intent"""
        action = intent.get('action')
        workflow = intent.get('workflow')
        
        # Use predefined workflow if available
        if workflow:
            wf = AgentWorkflow.get_workflow(workflow)
            if wf:
                steps = [
                    AgentThought(
                        step=i+1,
                        thought=s["description"],
                        action=s["action"],
                        tools=[s["tool"]] if s.get("tool") else []
                    )
                    for i, s in enumerate(wf["steps"])
                ]
                return AgentPlan(goal=wf["name"], steps=steps)
        
        # Default single-action plan
        if action == 'pentest' or action == 'full_scan':
            return AgentPlan(
                goal="Complete pentest",
                steps=[
                    AgentThought(step=1, thought="Reconnaissance", action="recon", tools=["whois_lookup"]),
                    AgentThought(step=2, thought="Port scanning", action="scan", tools=["quick_scan"]),
                    AgentThought(step=3, thought="Vulnerability assessment", action="vuln_scan", tools=["vuln_scan"]),
                    AgentThought(step=4, thought="Analysis and reporting", action="report", tools=[]),
                ]
            )
        
        return None

class AutoAgent:
    """Autonomous agent with enhanced capabilities, memory, and self-improvement"""
    
    def __init__(self):
        self.reasoning = ReasoningEngine()
        self.workflow = AgentWorkflow()
        self.tools = ToolRegistry()
        self.memory = AgentMemory()
        self.context: Dict = {}
        self.max_iterations = 10
        self.state = AgentState.IDLE
        self.current_thoughts: List[str] = []
        
    VALID_PENTEST_ACTIONS = {'scan', 'vuln_scan', 'web_scan', 'full_scan', 'recon', 'attack', 'pentest', 'osint', 'network_discovery', 'stealth_scan', 'quick_scan'}
    
    def _is_pentest_task(self, user_input: str) -> bool:
        """Check if the input is a valid pentesting task"""
        text_lower = user_input.lower()
        
        pentest_keywords = [
            'scan', 'escanea', 'vuln', 'web', 'host', 'port', 'network', 'red',
            'dispositivos', 'devices', 'recon', 'pentest', 'auditoria', 'exploit',
            'attack', 'hack', 'ip', 'domain', 'url', 'target', 'objetivo',
            'nmap', 'nikto', 'gobuster', 'whois', 'shodan', 'enum', 'subdomain',
            'cve', 'vulnerability', 'vulnerabilidad', 'security', 'seguridad',
            # Code related
            'code', 'script', 'genera', 'crea', 'create', 'shell', 'payload',
            'mejora', 'improve', 'optimiza', 'refactoriza', 'amplia', 'expande',
            # Research related
            'busca', 'search', 'investiga', 'como', 'how', 'que es', 'what is',
            'explica', 'explain', 'dime', 'solucion', 'problema', 'error',
            'ayuda', 'help', 'tutorial', 'guia', 'docs', 'documentacion'
        ]
        
        return any(kw in text_lower for kw in pentest_keywords)
    
    def process(self, user_input: str, ollama_client, model: str) -> str:
        """Main agent processing loop with chain-of-thought"""
        self.state = AgentState.THINKING
        
        # Guardrail: Reject non-pentesting tasks
        if not self._is_pentest_task(user_input):
            return """[!] Lo siento, solo puedo ayudarte con tareas de pentesting y seguridad:

- Escaneos de red y puertos (nmap)
- Descubrimiento de dispositivos en red
- Análisis de vulnerabilidades
- Enumeración de servicios y subdominios
- Búsqueda de exploits y CVEs
- Análisis web (nikto, whatweb)
- Consultas OSINT (Whois, Shodan, VirusTotal)
- Generación de código/payloads de seguridad

Para otras tareas, por favor usa otro modelo de IA."""
        
        # 1. Think - analyze the request with chain-of-thought
        thought_process = self.reasoning.think(user_input, self.context)
        self.current_thoughts.append(thought_process)
        
        # 2. Determine if this needs tool execution
        intent = self.reasoning._analyze_intent(user_input)
        
        # 3. Execute if needed
        if self._needs_execution(intent):
            self.state = AgentState.EXECUTING
            return self._execute_with_tools(user_input, intent, ollama_client, model)
        
        # 4. Otherwise, use pure LLM with context
        return self._chat_with_context(user_input, ollama_client, model)
    
    def _needs_execution(self, intent: Dict) -> bool:
        """Determine if tools need to be executed"""
        action = intent.get('action', '')
        return action in ['scan', 'vuln_scan', 'web_scan', 'full_scan', 'recon', 'attack', 'pentest', 'osint', 'network_discovery', 'research', 'improve_code']
    
    def _execute_with_tools(self, user_input: str, intent: Dict, ollama_client, model: str) -> str:
        """Execute with tool integration and iterative refinement"""
        results = []
        target = intent.get('target')
        
        if not target:
            # Try to extract from context
            if self.memory.targets_scanned:
                target = self.memory.targets_scanned[-1]
            else:
                return "[!] No target specified. Please provide an IP or domain."
        
        # Add to scanned targets
        if target not in self.memory.targets_scanned:
            self.memory.targets_scanned.append(target)
        
        action = intent.get('action')
        
        # Handle research/search action with web lookup
        if action == "research":
            return self._execute_research(user_input, ollama_client, model)
        
        # Handle code improvement
        if action == "improve_code":
            return self._execute_improve_code(user_input, ollama_client, model)
        
        # Use workflow if specified
        workflow_name = intent.get('workflow')
        if workflow_name:
            results.append(f"[*] Using workflow: {workflow_name}")
            return self._execute_workflow(workflow_name, target, ollama_client, model)
        
        # Execute single action based on intent
        action_str = action or "scan"
        result = self._execute_action(action_str, target)
        
        if isinstance(result, dict) and "error" in result:
            results.append(f"[!] Error: {result['error']}")
            # Try alternative
            results.append("[*] Trying alternative approach...")
            result = self._execute_action("quick_scan", target)
        
        # Store findings in memory
        if isinstance(result, dict):
            finding = Finding(
                target=target,
                severity="unknown",
                title=f"{action_str} on {target}",
                description=str(result)[:200],
                tool=action_str,
                evidence=str(result)[:500]
            )
            self.memory.add_finding(finding)
        
        # Generate analysis with LLM using context
        scan_results = self._format_results(result)
        
        return self._analyze_and_respond(target, action_str, scan_results, ollama_client, model)
    
    def _execute_workflow(self, workflow_name: str, target: str, ollama_client, model: str) -> str:
        """Execute a complete workflow"""
        workflow = self.workflow.get_workflow(workflow_name)
        if not workflow:
            return f"[!] Unknown workflow: {workflow_name}"
        
        results = [f"[*] Starting workflow: {workflow['name']}"]
        results.append(f"[*] Target: {target}\n")
        
        for i, step in enumerate(workflow['steps'], 1):
            self.state = AgentState.EXECUTING
            results.append(f"[{i}/{len(workflow['steps'])}] {step['description']}...")
            
            if step.get('tool'):
                tool = self.tools.get_tool(step['tool'])
                if tool:
                    try:
                        result = tool.execute(target)
                        formatted = self._format_results(result)
                        results.append(f"    Result: {formatted[:300]}...")
                        
                        # Evaluate and potentially iterate
                        eval_result = self.reasoning.evaluate_result(result)
                        if eval_result["findings"]:
                            results.append(f"    [!] Findings detected: {eval_result['findings']}")
                            for finding in eval_result["findings"]:
                                self.memory.add_vulnerability({
                                    "target": target,
                                    "type": finding,
                                    "step": step['description']
                                })
                    except Exception as e:
                        results.append(f"    [!] Error: {str(e)}")
            
            results.append("")
        
        # Final analysis
        self.state = AgentState.ANALYZING
        results.append("[*] Workflow completed. Generating analysis...")
        
        full_output = "\n".join(results)
        return self._analyze_and_respond(target, "workflow", full_output, ollama_client, model)
    
    def _execute_research(self, user_input: str, ollama_client, model: str) -> str:
        """Research/search for solutions using web search and LLM"""
        lines = ["[*] Investigando/analizando tu solicitud..."]
        lines.append(f"[*] Pregunta: {user_input}\n")
        
        # Extract the core question from the input
        clean_question = user_input.lower()
        for prefix in ['busca', 'search', 'investiga', 'como', 'how', 'que es', 'what is', 
                       'explica', 'explain', 'dime', 'tell me', 'ayuda', 'help', 'solucion']:
            clean_question = clean_question.replace(prefix, '').strip()
        
        if not clean_question:
            clean_question = user_input
        
        # Use LLM to research and provide detailed answer
        lines.append("[*] Investigando y buscando mejores soluciones...")
        
        messages = [
            {"role": "system", "content": """Eres un asistente de pentesting y seguridad informática.
Proporciona respuestas detalladas, prácticas y útiles.
Si no sabes algo, dilo honestamente.
Incluye comandos, ejemplos y soluciones prácticas cuando sea posible."""},
            {"role": "user", "content": f"""Investiga y responde a esta pregunta de seguridad/pentesting:

{user_input}

Proporciona:
1. Explicación clara
2. Comandos prácticos (si aplica)
3. Recursos adicionales
4. Soluciones paso a paso"""}
        ]
        
        try:
            response_chunks = []
            for chunk in ollama_client.chat(model, messages):
                response_chunks.append(chunk)
            llm_response = "".join(response_chunks)
            lines.append("\n" + llm_response)
        except Exception as e:
            lines.append(f"\n[!] Error con LLM: {str(e)}")
        
        return "\n".join(lines)
    
    def _execute_improve_code(self, user_input: str, ollama_client, model: str) -> str:
        """Improve, optimize or expand existing code"""
        lines = ["[*] Mejorando/optimizando código..."]
        lines.append(f"[*] Solicitud: {user_input}\n")
        
        # Check for existing code in context
        existing_code = ""
        if self.memory.recent_findings:
            for f in self.memory.recent_findings[-3:]:
                if f.evidence and '```' in f.evidence:
                    existing_code = f.evidence
                    break
        
        messages = [
            {"role": "system", "content": """Eres un experto en código de seguridad y pentesting.
Mejora, optimiza y expande código existente.
Cuando、改善as código:
1. Mantén la funcionalidad original
2. Agrega comentarios explicativos
3. Mejora la eficiencia y seguridad
4. Añade features relevantes
5. Devuelve el código completo mejorado

Devuelve SOLO el código mejorado entre etiquetas ```""" },
        ]
        
        # Build context
        if existing_code:
            user_msg = f"""Improve/optimize/expand this code:

{existing_code}

User request: {user_input}

Return ONLY the improved code, no explanations."""
        else:
            user_msg = f"""{user_input}

Since no existing code found, create an improved/complete version based on your request.
Return ONLY the code, no explanations."""

        messages.append({"role": "user", "content": user_msg})
        
        try:
            lines.append("[*] Generando código mejorado...")
            response_chunks = []
            for chunk in ollama_client.chat(model, messages):
                response_chunks.append(chunk)
            code_result = "".join(response_chunks)
            
            # Extract code block if present
            if '```' in code_result:
                lines.append("\n" + code_result)
            else:
                lines.append(f"\n```python\n{code_result}\n```")
            
            lines.append("\n[*] Código guardado en memoria para futuras referencias.")
            
            # Store in memory
            finding = Finding(
                target="code_improvement",
                severity="info",
                title=f"Code improvement: {user_input[:30]}",
                description=user_input,
                tool="improve_code",
                evidence=code_result
            )
            self.memory.add_finding(finding)
            
        except Exception as e:
            lines.append(f"\n[!] Error: {str(e)}")
        
        return "\n".join(lines)
    
    def _execute_action(self, action: str, target: str) -> Any:
        """Execute a single action using the appropriate tool"""
        tool_map = {
            'scan': 'quick_scan',
            'vuln_scan': 'vuln_scan',
            'web_scan': 'web_scan',
            'full_scan': 'full_scan',
            'quick_scan': 'quick_scan',
            'recon': 'whois_lookup',
            'osint': 'whois_lookup',
            'network_discovery': 'network_discovery',
        }
        
        tool_name = tool_map.get(action, 'quick_scan')
        tool = self.tools.get_tool(tool_name)
        
        if tool:
            try:
                return tool.execute(target)
            except Exception as e:
                return {"error": str(e), "action": action, "target": target}
        
        return {"error": f"No tool found for action: {action}"}
    
    def _format_results(self, result: Any) -> str:
        """Format execution results for display"""
        if isinstance(result, dict):
            if "error" in result:
                return f"Error: {result['error']}"
            return result.get("output", str(result))
        return str(result)
    
    def _analyze_and_respond(self, target: str, action: str, results: str, ollama_client, model: str) -> str:
        """Analyze results and generate response with LLM"""
        
        context = self.memory.get_context()
        
        prompt = f"""Eres un ANALISTA DE SEGURIDAD PROFESIONAL. Analiza los siguientes resultados:

CONTEXTO PREVIO:
{context}

ACCIÓN EJECUTADA: {action}
TARGET: {target}

RESULTADOS:
{results}

Proporciona:
1. RESUMEN EJECUTIVO (2-3 oraciones)
2. HALLAZGOS PRINCIPALES
3. SEVERIDAD (Critical/High/Medium/Low)
4. PRÓXIMOS PASOS RECOMENDADOS
5. REMEDIACIÓN SUGERIDA

Sé conciso y accionable."""
        
        messages = [
            {"role": "system", "content": "Eres un experto en ciberseguridad. Analiza y proporciona insights accionables."},
            {"role": "user", "content": prompt}
        ]
        
        analysis = []
        for chunk in ollama_client.chat(model, messages):
            analysis.append(chunk)
        
        full_analysis = "".join(analysis)
        
        # Add to memory
        finding = Finding(
            target=target,
            severity="unknown",
            title=f"Analysis: {action}",
            description=full_analysis[:200],
            tool=action,
            evidence=full_analysis[:500]
        )
        self.memory.add_finding(finding)
        
        return f"""[{'='*60}]
[*] TARGET: {target}
[*] ACCIÓN: {action}
[*] RESULTADOS:
{results}

[{'='*60}]
[*] ANÁLISIS:
{full_analysis}
[{'='*60}]"""
    
    def _chat_with_context(self, user_input: str, ollama_client, model: str) -> str:
        """Standard LLM chat with context from memory"""
        context = self.memory.get_context()
        
        prompt = f"""Contexto de la sesión:
{context}

Usuario: {user_input}

Proporciona una respuesta útil y accionable."""
        
        messages = [
            {"role": "system", "content": "Eres PTAI, asistente de pentesting. Sé útil, preciso y profesional."},
            {"role": "user", "content": prompt}
        ]
        
        response = []
        for chunk in ollama_client.chat(model, messages):
            response.append(chunk)
        
        return "".join(response)
    
    def run_workflow(self, workflow_name: str, target: str, ollama_client, model: str) -> str:
        """Execute a predefined workflow by name"""
        return self._execute_workflow(workflow_name, target, ollama_client, model)
    
    def get_status(self) -> Dict:
        """Get current agent status"""
        return {
            "state": self.state.value,
            "memory": {
                "targets_scanned": len(self.memory.targets_scanned),
                "vulnerabilities_found": len(self.memory.vulnerabilities_found),
                "recent_findings": len(self.memory.recent_findings)
            },
            "available_workflows": self.workflow.list_workflows(),
            "available_tools": self.tools.list_tools(),
            "tool_stats": {
                name: {
                    "usage": t.usage_count,
                    "success_rate": t.get_success_rate()
                }
                for name, t in self.tools.tools.items()
            }
        }
    
    def reset_memory(self):
        """Reset agent memory"""
        self.memory = AgentMemory()
        return "[*] Memory reset successfully"
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings filtered by severity"""
        return [f for f in self.memory.recent_findings 
                if f.severity.lower() == severity.lower()]
    
    def generate_summary(self) -> str:
        """Generate a summary of agent activity"""
        lines = ["=== AGENT SUMMARY ==="]
        lines.append(f"State: {self.state.value}")
        lines.append(f"Targets scanned: {len(self.memory.targets_scanned)}")
        
        if self.memory.vulnerabilities_found:
            lines.append(f"Vulnerabilities found: {len(self.memory.vulnerabilities_found)}")
        
        if self.memory.recent_findings:
            by_severity = {}
            for f in self.memory.recent_findings:
                by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            lines.append("Findings by severity:")
            for sev, count in sorted(by_severity.items()):
                lines.append(f"  {sev}: {count}")
        
        return "\n".join(lines)
    
    def suggest_next_actions(self, last_result: Any) -> List[str]:
        """Suggest next actions based on last result"""
        suggestions = []
        
        if isinstance(last_result, dict):
            output = last_result.get("output", "")
            error = last_result.get("error", "")
            
            if error:
                suggestions.append("retry_with_alternative")
                suggestions.append("try_different_target")
            
            if output:
                # Check for interesting patterns
                if "open port" in output.lower() or "22" in output or "80" in output or "443" in output:
                    suggestions.append("run_vuln_scan")
                    suggestions.append("run_service_enum")
                
                if "http" in output.lower() or "web" in output.lower():
                    suggestions.append("run_web_scan")
                    suggestions.append("run_dir_enum")
                
                if "vuln" in output.lower() or "cve" in output.lower():
                    suggestions.append("search_exploits")
                    suggestions.append("analyze_cve")
                
                if not suggestions:
                    suggestions.append("analyze_results")
                    suggestions.append("generate_report")
        
        return suggestions[:3]
    
    def self_correct(self, error: str, context: Dict) -> str:
        """Attempt self-correction based on error"""
        correction_prompt = f"""El agente encontró un error: {error}

Contexto:
{json.dumps(context, indent=2)}

¿Qué debería hacer el agente para recuperarse?
Proporciona:
1. Diagnóstico del problema
2. Acción correctiva sugerida
3. Herramienta alternativa a usar"""
        
        # This would be called with LLM for intelligent correction
        return f"[Self-Correction] Error: {error}. Consider using fallback tools."

# Global agent instance
auto_agent = AutoAgent()
