from typing import Dict, List, Optional, Callable
import time
from datetime import datetime

class AutomationTask:
    def __init__(self, name: str, description: str, function: Callable, 
                 category: str = "general"):
        self.name = name
        self.description = description
        self.function = function
        self.category = category
        self.last_run = None
        self.run_count = 0
    
    def execute(self, *args, **kwargs):
        self.last_run = datetime.now()
        self.run_count += 1
        return self.function(*args, **kwargs)


class AutomationRunner:
    def __init__(self):
        self.tasks: Dict[str, AutomationTask] = {}
        self.results: List[Dict] = []
    
    def register(self, name: str, description: str, category: str = "general"):
        def decorator(func: Callable):
            task = AutomationTask(name, description, func, category)
            self.tasks[name] = task
            return func
        return decorator
    
    def run_task(self, name: str, *args, **kwargs):
        if name not in self.tasks:
            return {"success": False, "error": f"Task {name} not found"}
        
        task = self.tasks[name]
        start = time.time()
        
        try:
            result = task.execute(*args, **kwargs)
            duration = time.time() - start
            
            task_result = {
                "task": name,
                "success": True,
                "result": result,
                "duration": duration,
                "timestamp": datetime.now().isoformat()
            }
            
            self.results.append(task_result)
            return task_result
            
        except Exception as e:
            duration = time.time() - start
            task_result = {
                "task": name,
                "success": False,
                "error": str(e),
                "duration": duration,
                "timestamp": datetime.now().isoformat()
            }
            
            self.results.append(task_result)
            return task_result
    
    def run_sequence(self, task_names: List[str]) -> List[Dict]:
        results = []
        for name in task_names:
            result = self.run_task(name)
            results.append(result)
            if not result["success"]:
                break
        return results
    
    def run_parallel(self, task_names: List[str]) -> List[Dict]:
        import concurrent.futures
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {executor.submit(self.run_task, name): name for name in task_names}
            results = []
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        return results
    
    def list_tasks(self, category: str = None) -> List[Dict]:
        tasks = []
        for name, task in self.tasks.items():
            if category is None or task.category == category:
                tasks.append({
                    "name": name,
                    "description": task.description,
                    "category": task.category,
                    "last_run": task.last_run.isoformat() if task.last_run else None,
                    "run_count": task.run_count
                })
        return tasks
    
    def get_results(self, limit: int = 10) -> List[Dict]:
        return self.results[-limit:]
    
    def clear_results(self):
        self.results = []


automation_runner = AutomationRunner()


def task(name: str, description: str = "", category: str = "general"):
    return automation_runner.register(name, description, category)


TASK_TEMPLATES = {
    "recon": [
        {
            "name": "quick_recon",
            "description": "Reconocimiento rápido",
            "steps": ["nmap_quick", "extract_ips", "check_services"]
        },
        {
            "name": "full_recon",
            "description": "Reconocimiento completo",
            "steps": ["nmap_full", "dns_enum", "subdomain_enum", "whois_lookup"]
        },
        {
            "name": "osint_recon",
            "description": "OSINT básico",
            "steps": ["shodan_lookup", "whois_lookup", "crt_lookup"]
        }
    ],
    "scanning": [
        {
            "name": "vuln_scan_basic",
            "description": "Escaneo básico de vulnerabilidades",
            "steps": ["nmap_vuln", "nikto_scan"]
        },
        {
            "name": "web_scan_full",
            "description": "Escaneo web completo",
            "steps": ["nmap_web", "nikto", "whatweb", "dirb"]
        }
    ],
    "exploitation": [
        {
            "name": "exploit_search",
            "description": "Buscar exploits",
            "steps": ["search_cve", "searchsploit"]
        }
    ],
    "reporting": [
        {
            "name": "quick_report",
            "description": "Reporte rápido",
            "steps": ["collect_findings", "generate_report"]
        }
    ]
}


def run_template(template_name: str, target: str = None) -> Dict:
    for category, templates in TASK_TEMPLATES.items():
        for template in templates:
            if template["name"] == template_name:
                return {
                    "template": template,
                    "category": category,
                    "target": target,
                    "status": "ready_to_run"
                }
    
    return {"error": f"Template {template_name} not found"}


def list_templates() -> Dict:
    return TASK_TEMPLATES


def get_template(template_name: str) -> Optional[Dict]:
    for category, templates in TASK_TEMPLATES.items():
        for template in templates:
            if template["name"] == template_name:
                return template
    return None
