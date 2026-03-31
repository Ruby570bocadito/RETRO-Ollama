import os
import sys
import re

if sys.platform == 'win32':
    os.system('chcp 65001 >nul')

from typing import List, Dict, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ollama_client import OllamaClient
from src.ai.backends.multi_backend import create_client, MultiBackendClient
from src.config import get_config
from src.ai.prompts import SYSTEM_PROMPTS
from src.tools.security import analyze_request, check_and_log, sanitize_target, validate_command
from src.cli_commands.scan_commands import ScanCommands
from src.tools.pentest import (
    quick_scan, full_scan, vuln_scan, web_scan, dir_scan,
    stealth_scan, port_scan, os_detect, search_exploits, aggressive_scan,
    get_available_tools, dns_enum, subdomain_enum, check_all_tools
)
from src.tools.system import (
    save_code, read_file, edit_file, list_files, 
    delete_file, execute_command, run_script,
    search_exploits as system_search, get_output_dir,
    ls_directory, get_processes, get_network_connections,
    get_system_info, check_tool, get_services, get_disk_info,
    get_network_info, check_pentest_env, get_wifi_networks,
    run_wsl, check_wsl_tools
)
from src.tools.apis import shodan_scan, virustotal_scan, hunter_lookup, crt_sh_lookup, whois_lookup
from src.tools.history import load_history, save_history, clear_history, search_history as history_search
from src.tools.sessions import create_session, load_session, list_sessions, add_target_to_session, save_result_to_session, get_session_results, add_chat_to_session, delete_session
from src.tools.cve import search_cve, search_by_keyword, get_recent_exploits, get_stats, format_cve, download_cisa_kev
from src.reports.generator import create_quick_report
from src.modes import get_current_mode, set_mode, get_mode_info, list_modes, get_mode_prompt, MODES
from src.cli_theme import (
    PRIMARY, PRIMARY_DIM, SECONDARY, ACCENT, ACCENT_ALT,
    SUCCESS, ERROR, WARNING, INFO, INFO_LIGHT,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_DIM, TEXT_MUTED,
    CAT_SCAN, CAT_GENERATE, CAT_ENUM, CAT_UTILS,
    MODE_CONFIG, SYMBOLS,
    fmt, bold, dim, status_ok, status_err, status_warn, status_info, label, cmd
)
from src.tools.compliance import ComplianceChecker
from src.tools.threat_intel import ThreatIntelligence
from src.tools.incident_response import IncidentResponse
from src.tools.metrics import SecurityMetrics
from src.tools import vuln_db
from src.tools.dependency_scanner import scan_dependencies

app = typer.Typer(help="PTAI - Pentesting AI Tool")
console = Console()

def get_client(backend_name=None):
    config = get_config()
    backend = backend_name or os.getenv("DEFAULT_BACKEND", config.ollama.host)
    if backend == "lmstudio":
        return create_client("lmstudio", host=config.ollama.host)
    elif backend == "llamacpp":
        return create_client("llamacpp", host="http://localhost:8080")
    else:
        return create_client("ollama", host=config.ollama.host)

ollama = get_client()
current_model = None
chat_history = load_history()[:50]

BANNER_SKULL = (
    "   [bold {mode_color}]───▐▀▄──────▄▀▌───▄▄▄▄▄▄▄\n"
    " ───▌▒▒▀▄▄▄▄▀▒▒▐▄▀▀▒██▒██▒▀▀▄\n"
    " ──▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄\n"
    " ──▌▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▀▄\n"
    " ▀█▒▒█▌▒▒█▒▒▐█▒▒▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌\n"
    " ▀▌▒▒▒▒▒▀▒▀▒▒▒▒▒▀▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐ ▄▄\n"
    " ▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄█▒█\n"
    " ▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▀\n"
    " ───▐▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▌\n"
    " ─────▀▄▄▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀[/]\n"
    "\n"
    "  [bold {mode_color}]{mode_name}[/bold {mode_color}]   {mode_desc}\n"
    "  [dim]v2.0  |  Powered by Local AI Models  |  Ollama - LM Studio - Llama.cpp[/dim]\n"
    "  " + "─" * 72 + "\n"
)

BANNER = BANNER_SKULL
MODE_BANNER = BANNER_SKULL


def print_banner(show_mode=True):
    from src.modes import get_current_mode, get_mode_info
    if show_mode:
        current = get_current_mode()
        mode_info = get_mode_info(current)
        console.print(BANNER.format(
            mode_name=mode_info['name'],
            mode_desc=mode_info['description'],
            mode_color=mode_info.get('color', '#808080')
        ))
    else:
        console.print(BANNER.format(
            mode_name="RETRO-OLLAMA",
            mode_desc="Pentesting AI Tool",
            mode_color=SECONDARY
        ))
    console.print()


def print_status():
    current = get_current_mode()
    mode_info = get_mode_info(current)
    mode_color = mode_info.get('color', '#808080')
    mode_icon = mode_info.get('icon', '')
    
    # Sleek inline status bar
    console.print(f"[dim]{'─' * 72}[/]")
    console.print(
        f"[bold {mode_color}]{mode_icon} {mode_info['name']}[/]  "
        f"[dim]|[/]  [dim]model:[/] [bold]{current_model or 'N/A'}[/]  "
        f"[dim]|[/]  [dim]output:[/] [dim]{get_output_dir()}[/]"
    )
    console.print(f"[dim]{'─' * 72}[/]")
    console.print()


def check_ollama():
    if not ollama.check_connection():
        backend_name = os.getenv("DEFAULT_BACKEND", "ollama")
        console.print(f"[red]X Cannot connect to {backend_name}[/red]")
        return False
    console.print(f"[green]OK Connected to {ollama.backend_name}[/green]")
    return True


def list_models():
    models = ollama.list_models()
    if not models:
        console.print("[yellow]No models available[/yellow]")
        return []
    
    table = Table(title="", box=box.SIMPLE, show_header=False)
    table.add_column("ID", style="#808080", justify="center", width=4)
    table.add_column("Model", style="#A0A0A0")
    table.add_column("Size", style="#606060", justify="right")
    for i, m in enumerate(models, 1):
        size_gb = m.get("size", 0) / (1024**3)
        table.add_row(f"[{i}]", m.get("name", "Unknown"), f"{size_gb:.2f} GB")
    console.print(table)
    return models


def select_model() -> str:
    global ollama
    
    # Professional backend selection panel
    backend_table = Table(show_header=False, box=None, padding=(0, 1))
    backend_table.add_column("Num", style="bold #00D4FF", width=4)
    backend_table.add_column("Backend", style="bold #E8E8E8", width=14)
    backend_table.add_column("Endpoint", style="#808080")
    backend_table.add_row("[1]", "Ollama",    "localhost:11434")
    backend_table.add_row("[2]", "LM Studio", "localhost:1234")
    backend_table.add_row("[3]", "Llama.cpp", "localhost:8080")
    
    console.print(Panel(
        backend_table,
        title=f"[bold {SECONDARY}]Select Backend[/]",
        border_style=TEXT_MUTED,
        box=box.ROUNDED,
        padding=(1, 2)
    ))
    console.print()
    backend_choice = console.input(f"[bold {SECONDARY}]>[/] [dim]Choose (1-3): [/dim]")
    
    if backend_choice == "2":
        os.environ["DEFAULT_BACKEND"] = "lmstudio"
        ollama = get_client("lmstudio")
        backend_name = "LM Studio"
    elif backend_choice == "3":
        os.environ["DEFAULT_BACKEND"] = "llamacpp"
        ollama = get_client("llamacpp")
        backend_name = "Llama.cpp"
    else:
        os.environ["DEFAULT_BACKEND"] = "ollama"
        ollama = get_client("ollama")
        backend_name = "Ollama"
    
    if not ollama.check_connection():
        console.print(f"[{ERROR}]X Cannot connect to {backend_name}[/{ERROR}]")
        sys.exit(1)
    
    console.print(f"[bold {SUCCESS}]OK Connected to {backend_name}[/bold {SUCCESS}]\n")
    
    models = ollama.list_models()
    if not models:
        console.print(f"[{WARNING}]No models available on this backend[/{WARNING}]")
        sys.exit(1)
    
    # Professional model table
    model_table = Table(title="", box=box.SIMPLE_HEAVY, show_header=True, border_style=TEXT_MUTED)
    model_table.add_column("#", style="dim", justify="center", width=3)
    model_table.add_column("Model", style=TEXT_PRIMARY)
    model_table.add_column("Size", style=INFO_LIGHT, justify="right")
    
    for i, m in enumerate(models, 1):
        name = m.get("name", "Unknown")
        size = m.get("size", 0) / (1024**3)
        model_table.add_row(str(i), name, f"{size:.2f} GB")
    
    console.print(model_table)
    console.print()
    
    console.print(f"[bold {SECONDARY}]>[/] [dim]Select model (1-{len(models)}): [/dim]")
    try:
        choice = int(console.input("\n> ")) - 1
        if 0 <= choice < len(models):
            selected = models[choice].get("name", "llama3.2")
            console.print(f"\n[bold {SUCCESS}]OK Selected: {selected}[/bold {SUCCESS}]\n")
            return selected
    except:
        pass
    selected = models[0].get("name", "llama3.2")
    console.print(f"\n[bold {SUCCESS}]OK Selected: {selected}[/bold {SUCCESS}]\n")
    return selected


def extract_ip_or_domain(text: str) -> Optional[str]:
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    ip_match = re.search(ip_pattern, text)
    if ip_match:
        return ip_match.group()
    
    domain_match = re.search(domain_pattern, text)
    if domain_match:
        return domain_match.group()
    
    return None


def extract_ports(text: str) -> Optional[str]:
    port_pattern = r'-p\s*([\d,]+)|puertos?\s*([\d,]+)|port\s*([\d,]+)'
    match = re.search(port_pattern, text, re.IGNORECASE)
    if match:
        for g in match.groups():
            if g:
                return g
    
    single_port = r'\b(\d+)\b'
    if re.search(r'\b(puerto|port)\s+\d+\b', text, re.IGNORECASE):
        match = re.search(r'(puerto|port)\s+(\d+)', text, re.IGNORECASE)
        if match:
            return match.group(2)
    
    return None


def detect_intent(text: str) -> Dict:
    msg_lower = text.lower()
    intent = {
        "action": None,
        "target": extract_ip_or_domain(text),
        "ports": extract_ports(text),
        "tool": None,
        "params": {}
    }
    
    greetings = ['hola', 'hello', 'hey', 'hi', 'buenas', 'que tal', 'wenas', 'buenos', 'buenas', 'que onda', 'holiwis']
    if any(text.strip().lower() == g or text.strip().lower().startswith(g + ' ') for g in greetings):
        intent["action"] = "greeting"
        return intent
    
    if any(w in msg_lower for w in ['escanea', 'scan', 'analiza', 'target', 'objetivo', 'mapea', 'haz un escaneo', 'hacer scan']):
        intent["action"] = "scan"
        
        if any(w in msg_lower for w in ['evasion', 'ids', 'ips', 'firewall', 'sigiloso', 'stealth', 'oculto', 'sin detected', 'indetectable', 'evadir']):
            intent["tool"] = "stealth"
        elif any(w in msg_lower for w in ['vuln', 'vulnerab', 'exploit', 'cve', 'vulnerabilidad', 'security']):
            intent["tool"] = "vuln"
        elif any(w in msg_lower for w in ['web', 'http', 'sitio', 'pagina', 'app', 'webapp', 'aplicación', 'dominio']):
            intent["tool"] = "web"
        elif any(w in msg_lower for w in ['directorio', 'dir', 'carpeta', 'content', 'ruta', 'enumerar']):
            intent["tool"] = "dir"
        elif any(w in msg_lower for w in ['completo', 'full', 'todo', 'profundo', 'all', 'exhaustivo', 'extensivo']):
            intent["tool"] = "full"
        elif any(w in msg_lower for w in ['rápido', 'quick', 'basic', 'simple', 'veloz', 'ligero']):
            intent["tool"] = "quick"
        elif any(w in msg_lower for w in ['puerto', 'port', 'puertos especificos', 'puertos']):
            intent["tool"] = "custom"
        elif any(w in msg_lower for w in ['os', 'sistema operativo', 'detectar so', 'operating system']):
            intent["tool"] = "os"
        elif any(w in msg_lower for w in ['sql', 'inyección', 'injection']):
            intent["tool"] = "sqlmap"
        elif any(w in msg_lower for w in ['dns', 'subdomain', 'subdominio', 'dnsenum']):
            intent["tool"] = "dns"
        else:
            intent["tool"] = "quick"
    
    elif any(w in msg_lower for w in ['busca', 'search', 'exploit', 'cve', 'busca exploit', 'busca vulnerable', 'buscar', 'searchsploit']):
        intent["action"] = "search"
        if intent["target"]:
            intent["params"]["keyword"] = intent["target"]
        else:
            keywords = ['apache', 'nginx', 'wordpress', 'mysql', 'ssh', 'ftp', 'smb', 'redis', 'postgres', 'windows', 'linux', 'elasticsearch', 'mongodb', 'docker', 'kubernetes', 'jupyter', 'grafana']
            for kw in keywords:
                if kw in msg_lower:
                    intent["params"]["keyword"] = kw
                    break
    
    elif any(w in msg_lower for w in ['automático', 'autopwn', 'todo junto', 'pentest completo', 'full audit', 'todo automatico', 'fullpentest', 'todo']):
        intent["action"] = "autopwn"
    
    elif any(w in msg_lower for w in ['ejecuta', 'run', 'corre', 'ejecutar', 'haz', 'ejecutame', 'corre esto']):
        intent["action"] = "execute"
    
    elif any(w in msg_lower for w in ['genera', 'crea', 'make', 'build', 'script', 'código', 'payload', 'shell', 'dame', 'necesito']):
        intent["action"] = "generate"
        if any(w in msg_lower for w in ['reverse', 'backdoor', 'bind', 'shell']):
            intent["params"]["type"] = "shell"
        elif any(w in msg_lower for w in ['exploit', 'poc', 'prueba']):
            intent["params"]["type"] = "exploit"
        elif any(w in msg_lower for w in ['tool', 'herramienta', 'automation', 'automatizacion']):
            intent["params"]["type"] = "tool"
        elif any(w in msg_lower for w in ['python', 'bash', 'powershell', 'script']):
            intent["params"]["type"] = "script"
        elif any(w in msg_lower for w in ['payload', 'metasploit', 'msfvenom']):
            intent["params"]["type"] = "payload"
        else:
            intent["params"]["type"] = "script"
    
    elif any(w in msg_lower for w in ['reporte', 'report', 'documenta', 'informe', 'documento', 'genera informe']):
        intent["action"] = "report"
    
    elif any(w in msg_lower for w in ['archivos', 'files', 'scripts', 'generados', 'lista', 'listar', 'mostrar']):
        intent["action"] = "list_files"
    
    elif any(w in msg_lower for w in ['analiza', 'analisis', 'analyze', 'resultados', 'que encontraste', 'interpretar']):
        intent["action"] = "analyze"
    
    elif any(w in msg_lower for w in ['fuerza bruta', 'brute', 'password', 'credencial', 'hydra', 'crack']):
        intent["action"] = "bruteforce"
    
    elif any(w in msg_lower for w in ['subdomain', 'subdominio', 'subdomainenum', 'amass', 'subfinder']):
        intent["action"] = "subdomain"
    
    elif any(w in msg_lower for w in ['dns', 'dnsenum', 'zona', 'registros']):
        intent["action"] = "dns"
    
    elif any(w in msg_lower for w in ['whois', 'registro', 'dueño', 'propietario']):
        intent["action"] = "whois"
    
    elif any(w in msg_lower for w in ['shodan', 'dispositivos', 'camaras', 'iot']):
        intent["action"] = "shodan"
    
    elif any(w in msg_lower for w in ['virustotal', 'virus', 'malware', 'reputation']):
        intent["action"] = "virustotal"
    
    elif any(w in msg_lower for w in ['email', 'emails', 'hunter', 'buscar emails']):
        intent["action"] = "hunter"
    
    elif any(w in msg_lower for w in ['certificado', 'ssl', 'tls', 'crt', 'certificados']):
        intent["action"] = "crt"
    
    elif any(w in msg_lower for w in ['proceso', 'procesos', 'task', 'running']):
        intent["action"] = "processes"
    
    elif any(w in msg_lower for w in ['red', 'network', 'ip', 'conexion', 'interfaces']):
        intent["action"] = "network"
    
    elif any(w in msg_lower for w in ['sistema', 'info', 'specs', 'hardware', 'maquina']):
        intent["action"] = "system"
    
    elif any(w in msg_lower for w in ['servicio', 'servicios', 'service', 'windows service']):
        intent["action"] = "services"
    
    elif any(w in msg_lower for w in ['disco', 'disk', 'espacio', 'storage', 'almacenamiento']):
        intent["action"] = "disk"
    
    elif any(w in msg_lower for w in ['ayuda', 'help', 'comandos', 'commands', 'que puedes hacer']):
        intent["action"] = "help"
    
    return intent


def auto_execute(intent: Dict) -> Optional[str]:
    raw_target = intent.get("target")
    target = sanitize_target(raw_target) if raw_target else None
    
    if raw_target and not target:
        return f"Target inválido: {raw_target}"
    
    tool = intent.get("tool")
    action = intent.get("action")
    params = intent.get("params", {})
    
    if action == "greeting":
        return None
    
    if action == "scan" and target:
        if tool == "vuln":
            console.print(f"[{ACCENT_ALT}]> Escaneo de vulnerabilidades en {target}...[/]")
            result = vuln_scan(target)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Vuln Scan - {target}", border_style=ERROR))
                return "Escaneo completado. Analizo los resultados?"
        
        elif tool == "web":
            console.print(f"[{ACCENT_ALT}]> Escaneo web en {target}...[/]")
            result = web_scan(target)
            for t, res in result.items():
                if res["success"]:
                    console.print(Panel(res["output"][:2000], title=f"{t} - {target}", border_style=ACCENT))
            return "Escaneo web completado."
        
        elif tool == "dir":
            console.print(f"[{ACCENT_ALT}]> Escaneo de directorios en {target}...[/]")
            result = dir_scan(target)
            if result["success"]:
                console.print(Panel(result["output"][:2000], title=f"Dir Scan - {target}", border_style=ACCENT))
            return "Escaneo de directorios completado."
        
        elif tool == "full":
            console.print(f"[{ACCENT_ALT}]> Escaneo completo en {target}...[/]")
            result = full_scan(target)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Full Scan - {target}", border_style=SUCCESS))
            return "Escaneo completo terminado."
        
        elif tool == "stealth":
            console.print(f"[{ACCENT_ALT}]> Escaneo con evasion de IDS/Firewall en {target}...[/]")
            console.print(f"[{ERROR}]! Usando tecnicas: fragmented, slow, source-port manipulation...[/]")
            result = execute_command(f"nmap -sS -T2 -f -g 53 --script=firewall-bypass {target}")
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Stealth Scan - {target}", border_style=ACCENT))
            else:
                result = execute_command(f"nmap -sS -T2 -f -p- {target}")
                if result["success"]:
                    console.print(Panel(result["output"][:3000], title=f"Stealth Scan - {target}", border_style=ACCENT))
                else:
                    console.print(Panel(result.get("error", "Error"), title="Error", border_style=ERROR))
            return "Escaneo sigiloso completado."
        
        elif tool == "os":
            console.print(f"[{ACCENT_ALT}]> Deteccion de SO en {target}...[/]")
            result = os_detect(target)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"OS Detect - {target}", border_style=SUCCESS))
            else:
                console.print(Panel(result.get("error", "Error"), title="Error", border_style=ERROR))
            return "Deteccion de SO completada."
        
        elif tool == "custom":
            ports = intent.get("ports")
            if ports:
                console.print(f"[{ACCENT_ALT}]> Escaneo de puertos {ports} en {target}...[/]")
                result = execute_command(f"nmap -sV -p {ports} {target}")
            else:
                console.print(f"[{ACCENT_ALT}]> Escaneo en {target}...[/]")
                result = quick_scan(target)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Scan - {target}", border_style=SUCCESS))
            else:
                console.print(Panel(result["error"][:1000], title="Error", border_style=ERROR))
            return "Escaneo completado."
        
        else:
            console.print(f"[{ACCENT_ALT}]> Escaneo rapido en {target}...[/]")
            result = quick_scan(target)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Quick Scan - {target}", border_style=SUCCESS))
            else:
                console.print(Panel(result["error"][:1000], title="Error", border_style=ERROR))
            return "Escaneo completado."
    
    elif action == "search":
        keyword = params.get("keyword") or target
        if keyword:
            console.print(f"[{ACCENT}]> Buscando exploits para {keyword}...[/]")
            result = search_exploits(keyword)
            if result["output"]:
                console.print(Panel(result["output"][:2500], title=f"Exploits: {keyword}", border_style=ACCENT))
            else:
                console.print(Panel(result["error"][:1000] if result.get("error") else "No se encontraron resultados", title="Resultado", border_style=ERROR))
            return "Busqueda completada."
    
    elif action == "autopwn" and target:
        console.print(f"[{ERROR}]* Pentest automatico en {target}...[/]")
        console.print(f"[{ACCENT_ALT}]1. Escaneo rapido...[/]")
        scan_result = quick_scan(target)
        
        console.print(f"[{ACCENT_ALT}]2. Escaneo de vulnerabilidades...[/]")
        vuln_result = vuln_scan(target)
        
        console.print(f"[{ACCENT_ALT}]3. Escaneo web...[/]")
        web_result = web_scan(target)
        
        console.print(f"[{ACCENT_ALT}]4. Escaneo de directorios...[/]")
        dir_result = dir_scan(target)
        
        all_output = f"Nmap:\n{scan_result.get('output', '')}\n\nVuln:\n{vuln_result.get('output', '')}\n\nDir:\n{dir_result.get('output', '')}"
        report_path = create_quick_report(target, {"output": all_output}, "autopwn")
        console.print(f"[{SUCCESS}]OK Reporte: {report_path}[/]")
        return f"Pentest automatico completado. Reporte en: {report_path}"
    
    elif action == "execute" and target:
        console.print(f"[{ACCENT_ALT}]> Ejecutando: {target}[/]")
        result = execute_command(target)
        if result["output"]:
            console.print(Panel(result["output"][:2000], title="Resultado", border_style=SUCCESS))
        if result["error"]:
            console.print(Panel(result["error"][:1000], title="Error", border_style=ERROR))
        return f"Codigo: {result['returncode']}"
    
    elif action == "generate":
        console.print(f"[{ACCENT_ALT}]> Generando codigo...[/]")
        params = intent.get("params", {})
        code_type = params.get("type", "script")
        code_prompt = f"Genera {code_type} para: {target or params.get('keyword', '')}"
        return f"generate_code|{code_prompt}"
    
    elif action == "report":
        if target:
            console.print(f"[{ACCENT_ALT}]> Generando reporte para {target}...[/]")
            result = quick_scan(target)
            report_path = create_quick_report(target, result, "nmap")
            console.print(f"[{SUCCESS}]OK Reporte: {report_path}[/]")
            return f"Reporte generado: {report_path}"
        else:
            return "Especifica un objetivo para el reporte. Ej: 'genera reporte de 192.168.1.1'"
    
    elif action == "list_files":
        files = list_files("all")
        if not files:
            return "No hay archivos generados."
        for cat, file_list in files.items():
            if file_list:
                console.print(f"\n[{ACCENT}]{cat.upper()}:[/]")
                for f in file_list:
                    console.print(f"  {f['name']} ({f['size']} bytes)")
        return None
    
    elif action == "analyze":
        if target:
            console.print(f"[{ACCENT}]> Analizando {target}...[/]")
            result = vuln_scan(target)
            if result["output"]:
                console.print(Panel(result["output"][:2000], title=f"Analisis - {target}", border_style=ACCENT))
            return "Analisis completado."
        return "Especifica que analizar."
    
    return None


def show_help():
    help_text = """
[bold #00FF88]╔══════════════════════════════════════════════════════════════════════╗[/]
[bold #00FF88]║                    PTAI - PENTESTING AI TOOL                         ║[/]
[bold #00FF88]║                  Powered by Ollama + Local AI Models                ║[/]
[bold #00FF88]╚══════════════════════════════════════════════════════════════════════╝[/]

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                              ESCANEOS                                      │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/scan <target>[/]       → Escaneo rápido nmap
  [cyan]/full <target>[/]      → Escaneo completo de puertos
  [cyan]/vuln <target>[/]      → Detección de vulnerabilidades
  [cyan]/web <target>[/]       → Análisis web (Nikto, WhatWeb)
  [cyan]/dir <target>[/]       → Enumeración de directorios
  [cyan]/stealth <target>[/]   → Escaneo con evasión de IDS
  [cyan]/os <target>[/]        → Detección de sistema operativo

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                           ENUMERACIÓN                                      │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/enum <target>[/]       → Enumeración completa
  [cyan]/dns <domain>[/]        → Enumeración de registros DNS
  [cyan]/subdomain <domain>[/] → Descubrimiento de subdominios
  [cyan]/autopwn <target>[/]   → Pentest automático
  [cyan]/fullpentest <target>[/] → Pentest completo (8 fases)

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                        GENERACIÓN DE CÓDIGO                               │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/code <desc>[/]        → Generar código/script
  [cyan]/shell <tipo>[/]       → Generar reverse/bind shell
  [cyan]/payload <tipo>[/]     → Generar payload
  [cyan]/script <desc>[/]      → Crear script de automatización

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                            APIS DE INTELIGENCIA                            │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/shodan <IP>[/]        → Shodan lookup
  [cyan]/virus <domain>[/]     → VirusTotal scan
  [cyan]/hunter <domain>[/]    → Hunter (buscar emails)
  [cyan]/crt <domain>[/]       → Certificados SSL (CRT.SH)
  [cyan]/whois <domain>[/]    → Whois lookup

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                         COMPLIANCE & AUDITORÍA                             │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/compliance <tipo>[/]  → Verificar compliance (cis, owasp, pci, nist)
  [cyan]/audit <target>[/]     → Auditoría de seguridad
  [cyan]/headers <domain>[/]  → Verificar security headers

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                         THREAT INTELLIGENCE                                │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/ioc <texto>[/]        → Extraer IOCs de texto
  [cyan]/threat <tipo>[/]      → Clasificar amenazas
  [cyan]/reputation <IP>[/]   → Verificar reputación de IP
  [cyan]/hashcheck <hash>[/]  → Analizar hash malicioso

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                         INCIDENT RESPONSE                                  │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/incident <tipo>[/]   → Iniciar respuesta a incidente
  [cyan]/ir-steps <tipo>[/]   → Ver pasos de respuesta
  [cyan]/escalate <severidad>[/] → Escalar incidente

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                            CVE & VULNERABILITIES                          │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/cve <ID>[/]           → Buscar CVE específico
  [cyan]/cve <keyword>[/]      → Buscar CVEs por palabra clave
  [cyan]/cveupdate[/]         → Actualizar base de datos CVE
  [cyan]/recent[/]            → Últimos exploits (30 días)
  [cyan]/vuln-db[/]           → Base de datos de vulnerabilidades

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                              SISTEMA                                      │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/run <cmd>[/]          → Ejecutar comando directo
  [cyan]/exec <tool> <args>[/] → Ejecutar herramienta
  [cyan]/tools[/]             → Listar herramientas disponibles
  [cyan]/search <term>[/]     → Buscar exploits (Exploit-DB)
  [cyan]/report <target>[/]   → Generar reporte
  [cyan]/reporthtml <target>[/] → Reporte HTML

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                            SESIONES & HISTORIAL                           │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/session [name][/]     → Crear/listar sesiones
  [cyan]/resume <name>[/]     → Reanudar sesión
  [cyan]/history[/]           → Ver historial de chat
  [cyan]/clearhistory[/]      → Borrar historial
  [cyan]/files[/]            → Archivos generados

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                              MODOS DE TRABAJO                             │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/mode <nombre>[/]     → Cambiar modo de trabajo
  [cyan]/modes[/]             → Listar modos disponibles
  [cyan]/models[/]           → Listar modelos disponibles
  [cyan]/backend <nombre>[/]  → Cambiar backend (ollama/lmstudio/llamacpp)

[#FFD93D]┌─────────────────────────────────────────────────────────────────────────────┐[/]
[#FFD93D]│                              OTROS                                        │[/]
[#FFD93D]└─────────────────────────────────────────────────────────────────────────────┘[/]
  [cyan]/help[/]              → Este menú
  [cyan]/clear[/]             → Limpiar pantalla
  [cyan]/exit[/]              → Salir

[A0A0A0]Salida por defecto:[/] {get_output_dir()}
[A0A0A0]Comandos soportados:[/] Escribe naturalmente, la IA detecta tu intención
"""
    console.print(help_text)


def _build_command_menu() -> str:
    """Build a modern command menu using Rich-compatible formatting."""
    return (
        f"[bold {CAT_SCAN}]SCANS          [/][bold {CAT_GENERATE}]GENERATION      [/][bold {CAT_ENUM}]ENUMERATION     [/][bold {CAT_UTILS}]UTILS[/]\n"
        f"{'─' * 16}  {'─' * 16}  {'─' * 16}  {'─' * 11}\n"
        f"[{CAT_SCAN}]/scan <tgt>    [/][{CAT_GENERATE}]/code <desc>    [/][{CAT_ENUM}]/enum <tgt>      [/][{CAT_UTILS}]/tools[/]\n"
        f"[{CAT_SCAN}]/vuln <tgt>    [/][{CAT_GENERATE}]/shell <type>   [/][{CAT_ENUM}]/dns <dom>       [/][{CAT_UTILS}]/run <cmd>[/]\n"
        f"[{CAT_SCAN}]/web <tgt>     [/][{CAT_GENERATE}]/payload <tgt>  [/][{CAT_ENUM}]/subdomain <d>   [/][{CAT_UTILS}]/search <q>[/]\n"
        f"[{CAT_SCAN}]/full <tgt>    [/][{CAT_GENERATE}]/script <desc>  [/][{CAT_ENUM}]/autopwn <tgt>   [/][{CAT_UTILS}]/report <t>[/]\n"
        f"[{CAT_SCAN}]/stealth <tgt> [/][{CAT_GENERATE}]                [/][{CAT_ENUM}]/shodan <ip>     [/][{CAT_UTILS}]/cve <id>[/]\n"
        f"{' ' * 16}  {' ' * 16}  [{CAT_ENUM}]/virus <dom>    [/][{CAT_UTILS}]/skills[/]\n"
        f"{' ' * 16}  {' ' * 16}  [{CAT_ENUM}]/hunter <dom>   [/][{CAT_UTILS}]/workflows[/]\n"
        f"{' ' * 16}  {' ' * 16}  [{CAT_ENUM}]/crt <domain>   [/]\n"
        f"\n[dim]Type /help for full command list - /modes to switch - /exit to quit[/]"
    )


def process_command(user_input: str) -> Optional[str]:
    parts = user_input.split(None, 1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    
    if cmd == "/help":
        console.print(Panel(
            _build_command_menu(),
            title=f"[bold {SECONDARY}]Command Reference[/]",
            border_style=SECONDARY,
            box=box.ROUNDED,
            padding=(0, 2)
        ))
        return None
    elif cmd == "/mode":
        if args:
            mode = args.lower()
            if set_mode(mode):
                mode_info = get_mode_info(mode)
                mode_color = mode_info.get('color', '#808080')
                console.print(f"[bold {mode_color}]{mode_info['icon']} Modo cambiado a: {mode_info['name']}[/]")
                console.print(f"{mode_info['description']}")
                print_banner()
                return None
            else:
                console.print("[red]Modo no valido. Modos disponibles:[/]")
                for m, info in MODES.items():
                    console.print(f"  {info['icon']} {m:12} - {info['name']}")
                return None
        else:
            current = get_current_mode()
            mode_info = get_mode_info(current)
            console.print(f"[bold]Modo actual: {mode_info['icon']} {mode_info['name']}[/]")
            console.print(f"\n[bold]Modos disponibles:[/]")
            for m, info in MODES.items():
                marker = ">" if m == current else " "
                console.print(f"  {marker} {m:12} - {info['icon']} {info['name']}")
            return None
    elif cmd == "/modes":
        console.print(f"\n[bold]Modos disponibles:[/]")
        for m, info in MODES.items():
            console.print(f"  {info['icon']} {m:12} - {info['name']}")
            console.print(f"         {info['description']}")
        return None
    elif cmd == "/models":
        list_models()
        return None
    elif cmd == "/setmodel":
        global current_model
        current_model = args if args else current_model
        return f"Modelo: {current_model}"
    elif cmd == "/backend":
        if args:
            backends = MultiBackendClient.get_available_backends()
            if args.lower() in backends:
                global ollama
                os.environ["DEFAULT_BACKEND"] = args.lower()
                ollama = get_client(args.lower())
                console.print(f"[green]OK Backend cambiado a: {args.lower()}[/]")
                if ollama.check_connection():
                    console.print(f"[green]OK Conexion exitosa[/]")
                else:
                    console.print(f"[red]X No se pudo conectar al backend[/]")
                return None
            else:
                console.print(f"[yellow]Backends disponibles: {', '.join(backends)}[/]")
                return None
        else:
            current = os.getenv("DEFAULT_BACKEND", "ollama")
            backends = MultiBackendClient.get_available_backends()
            console.print(f"[bold]Backend actual:[/] {current}")
            console.print(f"[bold]Backends disponibles:[/] {', '.join(backends)}")
            return "Usa /backend <nombre> para cambiar"
    elif cmd == "/files":
        files = list_files("all")
        for cat, file_list in files.items():
            if file_list:
                console.print(f"\n[{ACCENT}]{cat.upper()}:[/]")
                for f in file_list:
                    console.print(f"  {f['name']} ({f['size']} bytes)")
        return None
    elif cmd == "/output":
        return get_output_dir()
    elif cmd == "/clear":
        console.clear()
        print_banner()
        return None
    elif cmd in ["/exit", "/quit"]:
        console.print(f"[{ACCENT}]Hasta luego![/]")
        sys.exit(0)
    elif cmd in ["/code", "/genera", "/script", "/create"]:
        if args:
            console.print(f"[{ACCENT_ALT}]> Generando codigo: {args}...[/]")
            return f"generate_code|{args}"
        console.print(f"[{ACCENT_ALT}]> Generando codigo...[/]")
        return "generate_code|ayudame con scripts de pentesting"
    
    elif cmd in ["/shell", "/shells"]:
        if args:
            console.print(f"[{ACCENT_ALT}]> Generando shell: {args}...[/]")
            return f"generate_code|genera {args} shell para pentesting"
        console.print(f"[{ACCENT_ALT}]> Generando shell...[/]")
        return "generate_code|genera reverse shell en python"
    
    elif cmd in ["/payload", "/payloads"]:
        if args:
            console.print(f"[{ACCENT_ALT}]> Generando payload: {args}...[/]")
            return f"generate_code|genera payload {args} para pentesting"
        console.print(f"[{ACCENT_ALT}]> Generando payload...[/]")
        return "generate_code|genera un payload para linux"
    
    elif cmd in ["/scan", "/vuln", "/web", "/dir", "/full", "/stealth", "/os"]:
        return ScanCommands.handle_scan(cmd, args)
    
    elif cmd == "/autopwn":
        return ScanCommands.handle_autopwn(args)
    
    elif cmd == "/fullpentest":
        return ScanCommands.handle_fullpentest(args)
    
    elif cmd == "/enum":
        return ScanCommands.handle_enum(args)
    
    elif cmd == "/dns":
        if args:
            console.print(f"[{ACCENT}]> Enumeracion DNS en {args}...[/]")
            result = dns_enum(args)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"DNS Enum - {args}", border_style=SUCCESS))
            else:
                console.print(Panel(result.get("error", "Error"), title="Error", border_style=ERROR))
            return None
        return "Uso: /dns <domain> (ej: /dns ejemplo.com)"
    
    elif cmd == "/subdomain":
        if args:
            console.print(f"[{ACCENT}]> Buscando subdominios en {args}...[/]")
            result = subdomain_enum(args)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Subdomains - {args}", border_style=SUCCESS))
            else:
                console.print(Panel(result.get("error", "Error"), title="Error", border_style=ERROR))
            return None
        return "Uso: /subdomain <domain> (ej: /subdomain ejemplo.com)"
    
    elif cmd == "/run":
        if args:
            console.print(f"[{ACCENT_ALT}]> Ejecutando: {args}[/]")
            result = execute_command(args)
            if result["output"]:
                console.print(Panel(result["output"][:2500], title="Output", border_style=SUCCESS))
            if result.get("error") and result["returncode"] != 0:
                console.print(Panel(result["error"][:1000], title="Error", border_style=ERROR))
            return f"Codigo: {result['returncode']}"
        return "Uso: /run <comando>"
    
    elif cmd == "/search" or cmd == "/exploit":
        if args:
            console.print(f"[{ACCENT}]> Buscando exploits: {args}[/]")
            result = search_exploits(args)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Exploits for: {args}", border_style=ACCENT))
            else:
                console.print(Panel(result.get("error", "No se encontraron resultados"), title="Error", border_style=ERROR))
            return None
        return "Uso: /search <term>"
    
    elif cmd == "/report":
        if args:
            console.print(f"[{ACCENT_ALT}]> Generando reporte de {args}...[/]")
            result = quick_scan(args)
            report_path = create_quick_report(args, result, "nmap")
            console.print(f"[{SUCCESS}]OK Reporte: {report_path}[/]")
            return None
        return "Uso: /report <target>"
    
    elif cmd == "/exec":
        if args:
            parts = args.split(None, 1)
            tool_name = parts[0]
            tool_args = parts[1] if len(parts) > 1 else ""
            console.print(f"[{ACCENT_ALT}]> Ejecutando {tool_name}...[/]")
            from src.tools.pentest import run_tool
            result = run_tool(tool_name, tool_args)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"{tool_name} Output", border_style=SUCCESS))
            else:
                console.print(Panel(result.get("error", "Error ejecutando"), title="Error", border_style=ERROR))
            return None
        return "Uso: /exec <tool> <args> (ej: /exec nmap -sV 192.168.1.1)"
    
    elif cmd == "/tools":
        from src.tools.pentest import get_available_tools
        tools = get_available_tools()
        if tools:
            for cat, tool_list in tools.items():
                console.print(f"[{ACCENT}]{cat.upper()}:[/] {', '.join(tool_list)}")
        else:
            console.print("[yellow]No hay herramientas disponibles (instala Kali Linux o las herramientas manualmente)[/]")
        return None
    
    elif cmd == "/shodan":
        if args:
            console.print(f"[{ACCENT}]> Consultando Shodan: {args}[/]")
            result = shodan_scan(args)
            if result["success"]:
                console.print(Panel(result["output"], title=f"Shodan - {args}", border_style=SUCCESS))
            else:
                console.print(Panel(result["error"], title="Error", border_style=ERROR))
            return None
        return "Uso: /shodan <IP>"
    
    elif cmd == "/virus":
        if args:
            console.print(f"[{ACCENT}]> Escaneando en VirusTotal: {args}[/]")
            result = virustotal_scan(args)
            if result["success"]:
                console.print(Panel(result["output"], title=f"VirusTotal - {args}", border_style=SUCCESS))
            else:
                console.print(Panel(result["error"], title="Error", border_style=ERROR))
            return None
        return "Uso: /virus <domain>"
    
    elif cmd == "/hunter":
        if args:
            console.print(f"[{ACCENT}]> Buscando emails: {args}[/]")
            result = hunter_lookup(args)
            if result["success"]:
                console.print(Panel(result["output"], title=f"Hunter - {args}", border_style=SUCCESS))
            else:
                console.print(Panel(result["error"], title="Error", border_style=ERROR))
            return None
        return "Uso: /hunter <domain>"
    
    elif cmd == "/crt":
        if args:
            console.print(f"[{ACCENT}]> Buscando certificados: {args}[/]")
            result = crt_sh_lookup(args)
            if result["success"]:
                console.print(Panel(result["output"], title=f"CRT.SH - {args}", border_style=SUCCESS))
            else:
                console.print(Panel(result["error"], title="Error", border_style=ERROR))
            return None
        return "Uso: /crt <domain>"
    
    elif cmd == "/whois":
        if args:
            console.print(f"[{ACCENT}]> Whois: {args}[/]")
            result = whois_lookup(args)
            if result["success"]:
                console.print(Panel(result["output"], title=f"Whois - {args}", border_style=SUCCESS))
            else:
                console.print(Panel(result["error"], title="Error", border_style=ERROR))
            return None
        return "Uso: /whois <domain>"
    
    elif cmd == "/history":
        hist = load_history()
        if hist:
            console.print(f"[{ACCENT}]Historial ({len(hist)} mensajes):[/]")
            for msg in hist[-10:]:
                role = "U:" if msg["role"] == "user" else "A:"
                console.print(f"  {role} {msg['role']}: {msg['content'][:50]}...")
        else:
            console.print("[yellow]No hay historial[/]")
        return None
    
    elif cmd == "/clearhistory":
        clear_history()
        console.print("[green]Historial borrado[/]")
        return None
    
    elif cmd == "/session":
        if args:
            session_name = create_session(args)
            console.print(f"[green]OK Sesion creada: {session_name}[/]")
            return f"Usa /resume {session_name} para continuar"
        sessions = list_sessions()
        if sessions:
            console.print(f"[{ACCENT}]Sesiones guardadas ({len(sessions)}):[/]")
            for s in sessions[:10]:
                console.print(f"  {s['name']} - {s.get('created', '')[:10]} - {len(s.get('targets', []))} targets")
        else:
            console.print("[yellow]No hay sesiones[/]")
        return None
    
    elif cmd == "/resume":
        if args:
            session_data = load_session(args)
            if session_data:
                console.print(f"[green]OK Sesion cargada: {args}[/]")
                console.print(f"Targets: {', '.join(session_data.get('targets', []))}")
            else:
                console.print(f"[red]Sesion no encontrada: {args}[/]")
        else:
            console.print("[yellow]Uso: /resume <nombre>[/]")
        return None
    
    elif cmd == "/cve":
        if args:
            cve_id = args.strip().upper()
            if not cve_id.startswith("CVE-"):
                results = search_by_keyword(args)
                if results:
                    console.print(f"[{ACCENT}]Resultados para '{args}' ({len(results)}):[/]")
                    for cve in results[:10]:
                        console.print(f"  {cve['cveID']} - {cve['vendorProject']} - {cve['product']}")
                else:
                    console.print("[yellow]No se encontraron resultados[/]")
            else:
                cve = search_cve(cve_id)
                if cve:
                    console.print(Panel(format_cve(cve), title=f"CVE: {cve_id}", border_style=ACCENT))
                else:
                    console.print(f"[yellow]CVE no encontrado: {cve_id}[/]")
        else:
            stats = get_stats()
            console.print(f"[{ACCENT}]CISA KEV Database:[/]")
            console.print(f"  Total CVEs: {stats.get('total', 0)}")
        return None
    
    elif cmd == "/cveupdate":
        console.print(f"[{ACCENT_ALT}]Descargando CISA KEV...[/]")
        if download_cisa_kev(force=True):
            console.print("[green]OK Base de datos CVE actualizada[/]")
        else:
            console.print("[red]X Error al descargar[/]")
        return None
    
    elif cmd == "/recent":
        exploits = get_recent_exploits(30)
        console.print(f"[{ACCENT}]Explotados recientemente (ultimos 30 dias):[/]")
        for cve in exploits[:10]:
            console.print(f"  {cve['cveID']} - {cve['dateAdded']} - {cve['vendorProject']}")
        return None
    
    elif cmd == "/reporthtml":
        if args:
            from src.reports.generator import generate_report
            result = quick_scan(args)
            report_path = generate_report(
                target=args,
                findings=[],
                assessment_type="Escaneo automatico",
                format="html"
            )
            console.print(f"[{SUCCESS}]OK Reporte HTML: {report_path}[/]")
        else:
            console.print("[yellow]Uso: /reporthtml <target>[/]")
        return None
    
    elif cmd == "/compliance":
        if args:
            framework = args.lower()
            if framework not in ["cis", "owasp", "pci", "nist"]:
                console.print("[yellow]Framework valido: cis, owasp, pci, nist[/]")
                return None
            from src.tools.compliance import COMPLIANCE_CHECKS
            console.print(f"[{ACCENT_ALT}]Verificando compliance {framework.upper()}...[/]")
            framework_data = COMPLIANCE_CHECKS.get(framework, {})
            if framework == "cis":
                checks = framework_data.get("linux", []) + framework_data.get("windows", [])
            else:
                checks = framework_data.get("requirements", []) or framework_data.get("controls", []) or framework_data.get("headers", []) or []
            for check in checks[:15]:
                console.print(f"  [{check.get('severity', '?')[:3].upper():3}] {check.get('id', '')} - {check.get('title', '')[:50]}")
            console.print(f"[{SUCCESS}]OK Total checks: {len(checks)}[/]")
        else:
            console.print("[yellow]Uso: /compliance <cis|owasp|pci|nist>[/]")
            console.print("[cyan]Marcos de compliance disponibles:[/]")
            console.print("  cis   - CIS Benchmarks")
            console.print("  owasp - OWASP Top 10")
            console.print("  pci   - PCI-DSS")
            console.print("  nist  - NIST Framework")
        return None
    
    elif cmd == "/ioc":
        if args:
            ti = ThreatIntelligence()
            iocs = ti.extract_iocs(args)
            console.print(f"[{ACCENT}]IOCs extraidos:[/]")
            for ioc_type, values in iocs.items():
                if values:
                    console.print(f"  [{ioc_type.upper()}] {', '.join(values[:5])}")
        else:
            console.print("[yellow]Uso: /ioc <texto>[/]")
            console.print("[cyan]Ejemplo: /ioc 192.168.1.1 malicious.com virus@malware.com[/]")
        return None
    
    elif cmd == "/threat":
        if args:
            ti = ThreatIntelligence()
            classification = ti.classify_threat(args)
            if classification:
                c = classification[0] if isinstance(classification, list) else classification
                console.print(Panel(f"[bold]Tipo:[/] {c.get('type', 'unknown')}\n[bold]Categoria:[/] {c.get('category', 'N/A')}\n[bold]Severidad:[/] {c.get('severity', 'N/A')}", title=f"Clasificacion: {args}", border_style=ACCENT))
            else:
                console.print("[yellow]No se pudo clasificar[/]")
        else:
            console.print("[yellow]Uso: /threat <tipo>[/]")
            console.print("[cyan]Tipos: malware, phishing, ransomware, brute_force, etc.[/]")
        return None
    
    elif cmd == "/incident":
        if args:
            ir = IncidentResponse()
            incident = ir.create_incident(f"Incident: {args}", args, f"Incident created via CLI")
            console.print(Panel(f"[bold]ID:[/] {incident.id}\n[bold]Tipo:[/] {incident.incident_type}\n[bold]Severidad:[/] {incident.severity}", title="Nuevo Incidente", border_style=ERROR))
            steps = ir.get_response_steps(args)
            console.print(f"[{ACCENT_ALT}]Pasos de respuesta ({len(steps)}):[/]")
            for i, step in enumerate(steps, 1):
                console.print(f"  {i}. {step}")
        else:
            console.print("[yellow]Uso: /incident <tipo>[/]")
            console.print("[cyan]Tipos de incidente:[/]")
            console.print("  malware_infection, data_breach, phishing_attack")
            console.print("  ransomware, unauthorized_access, ddos_attack, insider_threat")
        return None
    
    elif cmd == "/ir-steps":
        if args:
            ir = IncidentResponse()
            steps = ir.get_response_steps(args)
            console.print(f"[{ACCENT}]Pasos de respuesta para {args}:[/]")
            for i, step in enumerate(steps, 1):
                console.print(f"  {i}. {step}")
        else:
            console.print("[yellow]Uso: /ir-steps <tipo_incidente>[/]")
        return None
    
    elif cmd == "/headers":
        if args:
            try:
                import requests
                console.print(f"[{ACCENT_ALT}]Verificando headers en {args}...[/]")
                if not args.startswith("http"):
                    args = "https://" + args
                resp = requests.head(args, timeout=10)
                headers = dict(resp.headers)
                checker = ComplianceChecker("owasp")
                results = checker.check_web_headers(headers)
                for r in results:
                    status = r.get("status", "unknown")
                    mark = f"[{SUCCESS}]OK[/]" if status == "pass" else f"[{ERROR}]X[/]" if status == "fail" else f"[{WARNING}]?[/]"
                    console.print(f"  {mark} {r.get('title', 'N/A')[:50]}")
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/]")
        else:
            console.print("[yellow]Uso: /headers <domain>[/]")
        return None
    
    elif cmd == "/vuln-db":
        from src.tools.vuln_db import VULNERABILITY_DATABASE
        console.print(f"[{ACCENT}]Vulnerability Database ({len(VULNERABILITY_DATABASE)} entries):[/]")
        for cve_id, vuln in list(VULNERABILITY_DATABASE.items())[:20]:
            console.print(f"  [{vuln.get('severity', '?')[:3].upper():3}] {cve_id}: {vuln.get('name', 'N/A')} (CVSS: {vuln.get('cvss', 0)})")
        console.print(f"\n[yellow]Total: {len(VULNERABILITY_DATABASE)} vulnerabilidades[/]")
        return None
    
    elif cmd == "/escalate":
        if args:
            ir = IncidentResponse()
            sev = args.lower()
            contact = ir.get_severity_info(sev)
            console.print(f"[{ERROR}]Escalando a severidad: {sev}[/]")
            console.print(f"[bold]Tiempo de respuesta:[/] {contact.get('response_time', 'N/A')}")
            console.print(f"[bold]Escalar a:[/] {contact.get('escalation', 'N/A')}")
        else:
            console.print("[yellow]Uso: /escalate <critical|high|medium|low>[/]")
        return None
    
    elif cmd == "/metrics":
        from src.tools.metrics import SecurityMetrics
        metrics = SecurityMetrics()
        metrics.record_scan("cli")
        metrics.record_finding("high")
        console.print(f"[{ACCENT}]Security Metrics:[/]")
        console.print("  Total scans: 1")
        console.print("  Findings: high=1, medium=0, low=0")
        console.print(f"  Output: {get_output_dir()}")
        return None
    
    elif cmd == "/ioc":
        if args:
            ti = ThreatIntelligence()
            iocs = ti.extract_iocs(args)
            console.print(f"[{ACCENT}]IOCs extraidos:[/]")
            for ioc_type, values in iocs.items():
                if values:
                    console.print(f"  [{ioc_type.upper()}] {', '.join(values[:5])}")
        else:
            console.print("[yellow]Uso: /ioc <texto>[/]")
            console.print("[cyan]Ejemplo: /ioc 192.168.1.1 malicious.com virus@malware.com[/]")
        return None
    
    elif cmd == "/threat":
        if args:
            ti = ThreatIntelligence()
            classification = ti.classify_threat(args)
            if classification:
                c = classification[0] if isinstance(classification, list) else classification
                console.print(Panel(f"[bold]Tipo:[/] {c.get('type', 'unknown')}\n[bold]Categoria:[/] {c.get('category', 'N/A')}\n[bold]Severidad:[/] {c.get('severity', 'N/A')}", title=f"Clasificacion: {args}", border_style=ACCENT))
            else:
                console.print("[yellow]No se pudo clasificar[/]")
        else:
            console.print("[yellow]Uso: /threat <tipo>[/]")
            console.print("[cyan]Tipos: malware, phishing, ransomware, brute_force, etc.[/]")
        return None
    
    elif cmd == "/incident":
        if args:
            ir = IncidentResponse()
            incident = ir.create_incident(f"Incident: {args}", args, f"Incident created via CLI")
            console.print(Panel(f"[bold]ID:[/] {incident.id}\n[bold]Tipo:[/] {incident.incident_type}\n[bold]Severidad:[/] {incident.severity}", title="Nuevo Incidente", border_style=ERROR))
            steps = ir.get_response_steps(args)
            console.print(f"[{ACCENT_ALT}]Pasos de respuesta ({len(steps)}):[/]")
            for i, step in enumerate(steps, 1):
                console.print(f"  {i}. {step}")
        else:
            console.print("[yellow]Uso: /incident <tipo>[/]")
            console.print("[cyan]Tipos de incidente:[/]")
            console.print("  malware_infection, data_breach, phishing_attack")
            console.print("  ransomware, unauthorized_access, ddos_attack, insider_threat")
        return None
    
    elif cmd == "/ir-steps":
        if args:
            ir = IncidentResponse()
            steps = ir.get_response_steps(args)
            console.print(f"[{ACCENT}]Pasos de respuesta para {args}:[/]")
            for i, step in enumerate(steps, 1):
                console.print(f"  {i}. {step}")
        else:
            console.print("[yellow]Uso: /ir-steps <tipo_incidente>[/]")
        return None
    
    elif cmd == "/headers":
        if args:
            try:
                import requests
                console.print(f"[{ACCENT_ALT}]Verificando headers en {args}...[/]")
                if not args.startswith("http"):
                    args = "https://" + args
                resp = requests.head(args, timeout=10)
                headers = dict(resp.headers)
                checker = ComplianceChecker("owasp")
                results = checker.check_web_headers(headers)
                for r in results:
                    status = r.get("status", "unknown")
                    mark = f"[{SUCCESS}]OK[/]" if status == "pass" else f"[{ERROR}]X[/]" if status == "fail" else f"[{WARNING}]?[/]"
                    console.print(f"  {mark} {r.get('title', 'N/A')[:50]}")
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/]")
        else:
            console.print("[yellow]Uso: /headers <domain>[/]")
        return None
    
    elif cmd == "/vuln-db":
        from src.tools.vuln_db import VULNERABILITY_DATABASE
        console.print(f"[{ACCENT}]Vulnerability Database ({len(VULNERABILITY_DATABASE)} entries):[/]")
        for cve_id, vuln in list(VULNERABILITY_DATABASE.items())[:20]:
            console.print(f"  [{vuln.get('severity', '?')[:3].upper():3}] {cve_id}: {vuln.get('name', 'N/A')} (CVSS: {vuln.get('cvss', 0)})")
        console.print(f"\n[yellow]Total: {len(VULNERABILITY_DATABASE)} vulnerabilidades[/]")
        return None
    
    elif cmd == "/escalate":
        if args:
            ir = IncidentResponse()
            sev = args.lower()
            contact = ir.get_severity_info(sev)
            console.print(f"[{ERROR}]Escalando a severidad: {sev}[/]")
            console.print(f"[bold]Tiempo de respuesta:[/] {contact.get('response_time', 'N/A')}")
            console.print(f"[bold]Escalar a:[/] {contact.get('escalation', 'N/A')}")
        else:
            console.print("[yellow]Uso: /escalate <critical|high|medium|low>[/]")
        return None
    
    elif cmd == "/metrics":
        from src.tools.metrics import SecurityMetrics
        metrics = SecurityMetrics()
        metrics.record_scan("test")
        metrics.record_finding("high")
        console.print(f"[{ACCENT}]Security Metrics Dashboard:[/]")
        console.print("  Scans: 1")
        console.print("  Findings by severity: high=1, medium=0, low=0")
        console.print(f"  Output: {get_output_dir()}")
        return None
    
    elif cmd == "/agent":
        from src.ai.agent import auto_agent
        if args:
            # Run agent with specific task
            console.print(f"[#808080]Running agent task: {args}[/]")
            result = auto_agent.process(args, ollama, current_model)
            console.print(result)
        else:
            console.print("[#808080]Agent Commands:[/]")
            console.print("  /agent <task> - Run autonomous agent task")
            console.print("  /workflow <name> <target> - Run workflow")
            console.print("  /status - Show agent status")
            console.print("  /reset - Reset agent memory")
            console.print("  /summary - Show activity summary")
        return None
    
    elif cmd == "/workflow":
        from src.ai.agent import auto_agent, AgentWorkflow
        if args:
            parts = args.split()
            if len(parts) >= 2:
                workflow_name = parts[0]
                target = " ".join(parts[1:])
                result = auto_agent.run_workflow(workflow_name, target, ollama, current_model)
                console.print(result)
            elif len(parts) == 1:
                # List workflows
                workflows = AgentWorkflow.list_workflows()
                console.print("[#808080]Available workflows:[/]")
                for wf in workflows:
                    console.print(f"  - {wf}")
            else:
                console.print("[yellow]Usage: /workflow <name> <target>[/]")
        else:
            workflows = AgentWorkflow.list_workflows()
            console.print("[#808080]Available workflows:[/]")
            for wf in workflows:
                console.print(f"  - {wf}")
            console.print("[yellow]Usage: /workflow <name> <target>[/]")
        return None
    
    elif cmd == "/status":
        from src.ai.agent import auto_agent
        status = auto_agent.get_status()
        console.print(Panel(
            f"""[#808080]AGENT STATUS[/]
State: {status['state']}
Targets scanned: {status['memory']['targets_scanned']}
Vulnerabilities: {status['memory']['vulnerabilities_found']}
Findings: {status['memory']['recent_findings']}

[#808080]Available:[/]
Workflows: {', '.join(status['available_workflows'][:3])}...
Tools: {len(status['available_tools'])}""",
            title="[#808080]Agent Status[/]",
            border_style="#404040"
        ))
        return None
    
    elif cmd == "/reset":
        from src.ai.agent import auto_agent
        result = auto_agent.reset_memory()
        console.print(f"[#808080]{result}[/]")
        return None
    
    elif cmd == "/summary":
        from src.ai.agent import auto_agent
        summary = auto_agent.generate_summary()
        console.print(Panel(summary, title="[#808080]Agent Summary[/]", border_style="#404040"))
        return None
    
    elif cmd == "/skills":
        from src.ai.skills import list_all_skills
        skills = list_all_skills()
        if args:
            for s in skills:
                if s['name'] == args or args in s['commands']:
                    console.print(Panel(
                        f"[#808080]Skill:[/] {s['name']}\n"
                        f"[#808080]Description:[/] {s['description']}\n"
                        f"[#808080]Category:[/] {s['category']}\n"
                        f"[#808080]Commands:[/] {', '.join(s['commands'])}\n"
                        f"[#808080]Tags:[/] {', '.join(s['tags'])}",
                        title=f"[#808080]{s['name']}[/]", border_style="#404040"
                    ))
                    return None
        console.print(Panel(
            f"[{INFO}]Available Skills ({len(skills)}):[/]\n\n" + 
            "\n".join([f"  [S] {s['name']:15} - {s['description'][:40]}" 
                      for s in skills]),
            title=f"[{INFO}]Skills[/]", border_style=TEXT_MUTED
        ))
        return None
    
    elif cmd == "/workflows":
        from src.ai.workflows import list_all_workflows
        workflows = list_all_workflows()
        if args:
            for wf in workflows:
                if wf['name'] == args:
                    steps = "\n".join([f"  {i+1}. {s['name']} ({s['tool']})" 
                                      for i, s in enumerate(wf['steps'])])
                    console.print(Panel(
                        f"[#808080]Workflow:[/] {wf['name']}\n"
                        f"[#808080]Description:[/] {wf['description']}\n"
                        f"[#808080]Category:[/] {wf['category']}\n"
                        f"[#808080]Steps:[/]\n{steps}",
                        title=f"[#808080]{wf['name']}[/]", border_style="#404040"
                    ))
                    return None
        console.print(Panel(
            f"[#808080]Available Workflows ({len(workflows)}):[/]\n\n" + 
            "\n".join([f"  {wf['name']:15} - {wf['description'][:50]}" 
                      for wf in workflows]),
            title="[#808080]Workflows[/]", border_style="#404040"
        ))
        return None
    
    elif cmd == "/findings":
        from src.ai.agent import auto_agent
        findings = auto_agent.memory.recent_findings
        if findings:
            console.print(f"[#808080]Recent Findings ({len(findings)}):[/]")
            for i, f in enumerate(findings[-10:], 1):
                console.print(f"  {i}. [{f.severity.upper()}] {f.title}")
        else:
            console.print("[yellow]No findings yet[/]")
        return None
    
    if cmd.startswith("/"):
        return f"Comando: {cmd}. Escribe /help"
    
    return "continue"


def get_loading_animation():
    import itertools
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    for frame in itertools.cycle(frames):
        yield frame


FUNCTIONS = {
    "ls_directory": ls_directory,
    "get_processes": get_processes,
    "get_network_connections": get_network_connections,
    "get_system_info": get_system_info,
    "check_tool": check_tool,
    "get_services": get_services,
    "get_disk_info": get_disk_info,
    "get_network_info": get_network_info,
    "check_pentest_env": check_pentest_env,
    "check_wsl_tools": check_wsl_tools,
    "run_wsl": run_wsl,
    "wsl": run_wsl,
    "execute_command": execute_command,
    "save_code": save_code,
    "read_file": read_file,
    "edit_file": edit_file,
    "delete_file": delete_file,
    "list_files": list_files,
    "search_exploits": search_exploits,
    "quick_scan": quick_scan,
    "vuln_scan": vuln_scan,
    "web_scan": web_scan,
    "dir_scan": dir_scan,
    "full_scan": full_scan,
    "os_detect": os_detect,
    "port_scan": port_scan,
}


AUTO_FUNCTIONS = {
    ("carpeta", "directorio", "folder", "ls", "contenido de", "lista", "escritorio", "desktop", "archivos", "ficheros", "enumerate", "enumera", "que tienes", "que hay", "tienes instalado", "tenes", "que archivos"): lambda p=os.path.expanduser("~/Desktop"): ls_directory(p),
    ("proceso", "procesos", "process", "tasks"): get_processes,
    ("disco", "disco", "disk", "espacio", "almacenamiento"): get_disk_info,
    ("servicio", "servicios", "service", "services"): get_services,
    ("red", "conexiones", "connections", "netstat", "ip"): get_network_info,
    ("sistema", "info", "informacion", "systeminfo", "specs"): get_system_info,
    ("herramienta", "herramientas", "tools", "tool", "instalada", "disponible", "descargadas"): check_all_tools,
    ("wsl", "linux", "kali", "ubuntu", "ejecuta en", "corre en"): check_wsl_tools,
    ("wifi", "wireless", "redes wifi"): get_wifi_networks,
    ("wifi", "redes", "networks"): get_wifi_networks,
    ("instalado", "tool", "nmap", "python", "git"): lambda t="nmap": check_tool(t or "nmap"),
}


def auto_detect_and_execute(message: str) -> tuple:
    if message.strip().startswith('/'):
        return False, ""
    
    msg_lower = message.lower()
    results = []
    executed_something = False
    
    for keywords, func in AUTO_FUNCTIONS.items():
        if any(k in msg_lower for k in keywords):
            try:
                if "carpeta" in msg_lower or "directorio" in msg_lower or "folder" in msg_lower or "contenido de" in msg_lower or "ls " in msg_lower or msg_lower.endswith("ls"):
                    import re
                    path_match = re.search(r'[A-Za-z]:[\\\/][^\s]+|/[~]?\w+', message)
                    path = path_match.group() if path_match else "."
                    result = func(path)
                    executed_something = True
                elif "instalado" in msg_lower or "tool" in msg_lower:
                    import re
                    tool_match = re.search(r'(nmap|python|git|node|npm|java|go|rust|curl|wget|mysql|postgres|mongodb|redis|docker|kali|nikto|sqlmap|hydra|msfconsole)', msg_lower)
                    tool = tool_match.group() if tool_match else "nmap"
                    result = func(tool)
                    executed_something = True
                else:
                    result = func()
                    executed_something = True
                
                if isinstance(result, dict):
                    output = result.get("output", str(result))
                    if isinstance(output, list):
                        lines = []
                        for item in output:
                            if isinstance(item, dict):
                                name = item.get('name', '')
                                ftype = item.get('type', 'file')
                                size = item.get('size', 0)
                                lines.append(f"{'[DIR]' if ftype == 'dir' else '[FILE]'} {name} ({size} bytes)")
                            else:
                                lines.append(str(item))
                        output = "\n".join(lines)
                    if result.get("error"):
                        output += f"\nError: {result.get('error')}"
                    results.append(output)
                else:
                    results.append(str(result))
            except Exception as e:
                results.append(f"Error: {str(e)}")
                executed_something = True
    
    if executed_something:
        return True, "\n\n".join(results)
    return False, ""


def execute_function_call(response: str) -> tuple:
    import re
    
    pattern = r'\[FUNC:(\w+)\((.*?)\)\]'
    matches = re.findall(pattern, response)
    
    if not matches:
        return response, []
    
    results = []
    for func_name, params_str in matches:
        if func_name in FUNCTIONS:
            try:
                func = FUNCTIONS[func_name]
                params = [p.strip().strip("'\"") for p in params_str.split(",") if p.strip()]
                params = [p for p in params if p and p != "None"]
                
                result = func(*params) if params else func()
                
                if isinstance(result, dict):
                    result_str = result.get("output", str(result))
                    if result.get("error"):
                        result_str += f"\nError: {result.get('error')}"
                    results.append(f"{func_name}: {result_str}")
                else:
                    results.append(f"{func_name}: {result}")
            except Exception as e:
                results.append(f"Error en {func_name}: {str(e)}")
    
    for match in matches:
        response = response.replace(f"[FUNC:{match[0]}({match[1]})]", "")
    
    return response, results


def chat_with_ai(message: str, model: str) -> Optional[str]:
    if not message or not message.strip():
        return None
    
    check_and_log(message, model)
    
    executed, result = auto_detect_and_execute(message)
    if executed:
        console.print(Panel(str(result)[:3000], title="[green]Resultado[/]", border_style="#00FF88"))
        return None
    
    cmd_result = process_command(message)
    if cmd_result == "continue":
        pass
    elif cmd_result and cmd_result.startswith("continue_scan|"):
        parts = cmd_result.split("|")
        tool = parts[1].replace("/", "")  
        target = parts[2]
        if tool == "scan":
            result = quick_scan(target)
        elif tool == "vuln":
            result = vuln_scan(target)
        elif tool == "web":
            result = web_scan(target)
        elif tool == "dir":
            result = dir_scan(target)
        else:
            result = quick_scan(target)
        if result["success"]:
            console.print(Panel(result["output"][:3000], title=f"{tool.upper()} - {target}", border_style=SUCCESS))
        return None
    elif cmd_result and cmd_result.startswith("continue_autopwn|"):
        target = cmd_result.split("|")[1]
        console.print(f"[{ERROR}]* Pentest automatico en {target}...[/]")
        scan_result = quick_scan(target)
        vuln_result = vuln_scan(target)
        web_result = web_scan(target)
        all_output = f"Nmap:\n{scan_result.get('output', '')}\n\nVuln:\n{vuln_result.get('output', '')}"
        report_path = create_quick_report(target, {"output": all_output}, "autopwn")
        console.print(f"[{SUCCESS}]OK Reporte: {report_path}[/]")
        return f"Pentest completado. Reporte en: {report_path}"
    elif cmd_result and cmd_result.startswith("continue_fullpentest|"):
        target = cmd_result.split("|")[1]
        console.print(f"[{ERROR}]* PENTEST COMPLETO en {target}...[/]")
        
        console.print(f"[{ACCENT_ALT}]1. Escaneo rapido...[/]")
        scan_result = quick_scan(target)
        
        console.print(f"[{ACCENT_ALT}]2. Escaneo completo de puertos...[/]")
        full_result = full_scan(target)
        
        console.print(f"[{ACCENT_ALT}]3. Deteccion de SO...[/]")
        os_result = os_detect(target)
        
        console.print(f"[{ACCENT_ALT}]4. Escaneo de vulnerabilidades...[/]")
        vuln_result = vuln_scan(target)
        
        console.print(f"[{ACCENT_ALT}]5. Escaneo web...[/]")
        web_result = web_scan(target)
        
        console.print(f"[{ACCENT_ALT}]6. Escaneo de directorios...[/]")
        dir_result = dir_scan(target)
        
        console.print(f"[{ACCENT_ALT}]7. Enumeracion DNS...[/]")
        dns_result = dns_enum(target)
        
        console.print(f"[{ACCENT_ALT}]8. Enumeracion de subdominios...[/]")
        sub_result = subdomain_enum(target)
        
        all_output = f"""=== PENTEST COMPLETO - {target} ===

[QUICK SCAN]
{scan_result.get('output', '')}

[FULL SCAN]
{full_result.get('output', '')}

[OS DETECTION]
{os_result.get('output', '')}

[VULNERABILITIES]
{vuln_result.get('output', '')}

[WEB SCAN]
{web_result.get('output', '')}

[DIRECTORY SCAN]
{dir_result.get('output', '')}

[DNS ENUMERATION]
{dns_result.get('output', '')}

[SUBDOMAIN ENUMERATION]
{sub_result.get('output', '')}"""
        
        report_path = create_quick_report(target, {"output": all_output}, "fullpentest")
        console.print(f"[{SUCCESS}]OK Reporte: {report_path}[/]")
        return f"Pentest COMPLETO terminado. Reporte en: {report_path}"
    elif cmd_result and cmd_result.startswith("generate_code|"):
        prompt = cmd_result.split("|")[1]
        console.print(f"[{ACCENT_ALT}]> Generando: {prompt}...[/]")
        
        use_model: str = model
        restricted_terms = ['keylog', 'malware', 'ransomware', 'trojan', 'virus', 'backdoor', 'spyware']
        if any(term in prompt.lower() for term in restricted_terms):
            available = ollama.list_models()
            for m in available:
                name = m.get('name') or ''
                if 'dolphin' in name.lower() or 'mixtral' in name.lower():
                    use_model = name
                    console.print(f"[{ACCENT_ALT}]> Usando modelo: {use_model}[/]")
                    break
        
        code_prompt = f"""SOLO CODIGO. NADA DE EXPLICACIONES.

Genera SOLO el codigo. Sin texto antes o despues.
Solo el bloque de codigo entre etiquetas.

Lenguaje: detecta el mejor para lo solicitado
Formato: ```lenguaje
codigo
```"""

        messages = [
            {"role": "system", "content": code_prompt},
            {"role": "user", "content": f"{prompt}\n\nDa SOLO el codigo. Sin explicaciones. Sin warnigs. Solo codigo."}
        ]
        
        console.print(f"[{ACCENT_ALT}]> Generando codigo...[/]")
        
        import time
        start_time = time.time()
        response = []
        
        try:
            for chunk in ollama.chat(use_model, messages):
                response.append(chunk)
        except Exception as e:
            console.print(f"[{ERROR}]Error en generacion: {str(e)}[/]")
            return f"Error: {str(e)}"
        
        elapsed = int(time.time() - start_time)
        full_response = "".join(response)
        char_count = len(full_response)
        
        console.print(f"\n[{SUCCESS}]OK Completado en {elapsed}s [{char_count} chars][/]")
        
        if full_response.strip():
            sys.stdout.write(full_response)
            sys.stdout.flush()
            console.print(Panel(full_response[:5000], title="Respuesta IA", border_style=SUCCESS))
        
        code_match = None
        detected_lang = "py"
        
        lang_patterns = [
            ('```python', 'py'), ('```python3', 'py'), ('```py', 'py'),
            ('```bash', 'sh'), ('```sh', 'sh'), ('```shell', 'sh'), ('```zsh', 'sh'),
            ('```powershell', 'ps1'), ('```ps1', 'ps1'), ('```pwsh', 'ps1'),
            ('```csharp', 'cs'), ('```c#', 'cs'), ('```cs', 'cs'),
            ('```c', 'c'), ('```c++', 'cpp'), ('```cpp', 'cpp'),
            ('```javascript', 'js'), ('```js', 'js'), ('```node', 'js'),
            ('```typescript', 'ts'), ('```ts', 'ts'),
            ('```java', 'java'), ('```kotlin', 'kt'), ('```scala', 'scala'),
            ('```go', 'go'), ('```golang', 'go'), ('```rust', 'rs'),
            ('```ruby', 'rb'), ('```php', 'php'), ('```perl', 'pl'),
            ('```lua', 'lua'), ('```r', 'r'), ('```swift', 'swift'),
            ('```html', 'html'), ('```css', 'css'), ('```sql', 'sql'),
            ('```yaml', 'yaml'), ('```yml', 'yaml'), ('```json', 'json'),
            ('```xml', 'xml'), ('```dockerfile', 'docker'), ('```asm', 'asm'),
            ('```', 'txt')
        ]
        
        for pattern, lang in lang_patterns:
            if pattern in full_response:
                parts = full_response.split(pattern)
                if len(parts) > 1:
                    code_match = parts[1].split('```')[0] if '```' in parts[1] else parts[1]
                    detected_lang = lang
                    break
        
        if not code_match or len(code_match) < 20:
            code_match = full_response
            if '#!/bin/bash' in full_response or '#!/usr/bin/env bash' in full_response:
                detected_lang = 'sh'
            elif '#!/usr/bin/python' in full_response or '#!/bin/python' in full_response:
                detected_lang = 'py'
            elif 'import socket' in full_response or 'import os' in full_response:
                detected_lang = 'py'
            elif '$socket' in full_response or 'Get-Process' in full_response:
                detected_lang = 'ps1'
            elif 'nmap' in full_response.lower() or 'ping' in full_response.lower() or 'curl' in full_response.lower() or 'wget' in full_response.lower():
                detected_lang = 'sh'
            elif full_response.strip().startswith('```'):
                detected_lang = 'txt'
        
        if code_match:
            if detected_lang == 'txt' or len(code_match.strip()) < 30:
                console.print(f"[{WARNING}]! Codigo muy corto para guardar, mostrando directamente:[/]")
                console.print(Panel(code_match.strip()[:2000], title="Codigo generado", border_style=SUCCESS))
            else:
                ext = f".{detected_lang}"
                stop_words = ['un', 'una', 'para', 'de', 'el', 'la', 'creame', 'genera', 'make', 'me', 'un', 'un', 'un', 'codigo', 'script']
                name_words = [w for w in prompt.split() if w.lower() not in stop_words and len(w) > 2]
                name = "_".join(name_words[:3]) if name_words else "script"
                filename = f"{name}{ext}"
                
                from src.tools.system import save_code
                filepath = save_code(code_match, filename, "scripts")
                console.print(f"[{SUCCESS}]OK Codigo guardado en: {filepath}[/]")
        
        return None
    elif cmd_result:
        return cmd_result
    elif cmd_result is None:
        return None
    
    intent = detect_intent(message)
    auto_result = auto_execute(intent)
    if auto_result:
        if auto_result.startswith("generate_code|"):
            prompt = auto_result.split("|")[1]
            console.print(f"[{ACCENT_ALT}]> Generando: {prompt}...[/]")
            
            use_model: str = model
            restricted_terms = ['keylog', 'malware', 'ransomware', 'trojan', 'virus', 'backdoor', 'spyware']
            if any(term in prompt.lower() for term in restricted_terms):
                available = ollama.list_models()
                for m in available:
                    name = m.get('name') or ''
                    if 'dolphin' in name.lower() or 'mixtral' in name.lower():
                        use_model = name
                    console.print(f"[{ACCENT_ALT}]> Usando modelo: {use_model}[/]")
                    break
            
            code_prompt = f"""SOLO CODIGO. NADA DE EXPLICACIONES.

Genera SOLO el codigo. Sin texto antes o despues.
Solo el bloque de codigo entre etiquetas.

Lenguaje: detecta el mejor para lo solicitado
Formato: ```lenguaje
codigo
```"""

            messages = [
                {"role": "system", "content": code_prompt},
                {"role": "user", "content": f"{prompt}\n\nDa SOLO el codigo. Sin explicaciones. Sin warnigs. Solo codigo."}
            ]
            
            import time
            start_time = time.time()
            response = []
            
            console.print(f"[{ACCENT_ALT}]> Generando codigo...[/]")
            
            try:
                for chunk in ollama.chat(use_model, messages):
                    response.append(chunk)
                    print(chunk, end="", flush=True)
            except Exception as e:
                console.print(f"[{ERROR}]Error en generacion: {str(e)}[/]")
                return f"Error: {str(e)}"
            
            elapsed = int(time.time() - start_time)
            full_response = "".join(response)
            char_count = len(full_response)
            
            console.print(f"\n[{SUCCESS}]OK Completado en {elapsed}s [{char_count} chars][/]")
            
            if full_response.strip():
                console.print(Panel(full_response[:5000], title="Codigo generado", border_style=SUCCESS))
            
            return None
        return auto_result
    
    current_mode = get_current_mode()
    mode_info = get_mode_info(current_mode)
    system_prompt = get_mode_prompt(current_mode)

    system_prompt += f"""

MODO ACTUAL: {mode_info['name']}
{mode_info['description']}

Puedes ejecutar VARIAS funciones en secuencia para completar una tarea.

USA EL FORMATO DE FUNCIONES:
[FUNC:nombre_funcion(param1,param2)]

Funciones adicionales:
- [FUNC:execute_command("cmd")] - Ejecuta comandos
- [FUNC:ls_directory("path")] - Lista directorios
- [FUNC:get_processes()] - Procesos
- [FUNC:get_system_info()] - Info sistema
- [FUNC:get_network_info()] - Info red
- [FUNC:check_tool("nombre")] - Verifica herramienta
- [FUNC:save_code("contenido", "nombre", "categoria")] - Guarda archivo

HAZ, NO DIGAS QUE HARAS!"""

    messages = [
        {"role": "system", "content": system_prompt},
        *chat_history[-8:],
        {"role": "user", "content": message}
    ]
    
    import time
    start_time = time.time()
    response = []
    
    # Clean thinking indicator
    console.print()
    console.print(f"[dim]thinking...[/]")
    
    for chunk in ollama.chat(model, messages):
        response.append(chunk)
        print(chunk, end="", flush=True)
    
    full_response = "".join(response)
    
    clean_response, func_results = execute_function_call(full_response)
    
    if func_results:
        console.print()
        console.print(Panel("\n".join(func_results), title=f"[{SUCCESS}]Function Results[/]", border_style=SUCCESS, box=box.SIMPLE))
        console.print()
        messages.append({"role": "assistant", "content": clean_response})
        messages.append({"role": "user", "content": f"Resultados de las funciones: {func_results}"})
        
        response = []
        console.print(f"[dim]processing results...[/]")
        
        for chunk in ollama.chat(model, messages):
            response.append(chunk)
            print(chunk, end="", flush=True)
        
        full_response = "".join(response)
    
    elapsed = int(time.time() - start_time)
    char_count = len(full_response)
    words = len(full_response.split())
    
    # Clean metrics footer
    console.print()
    console.print(f"[dim]{'─' * 60}[/]")
    console.print(
        f"[dim]time[/] [bold {SUCCESS}]{elapsed}s[/]  "
        f"[dim]words[/] [bold {SECONDARY}]{words}[/]  "
        f"[dim]chars[/] [bold {ACCENT}]{char_count}[/]"
    )
    console.print()
    
    chat_history.append({"role": "user", "content": message})
    chat_history.append({"role": "assistant", "content": full_response})
    
    save_history(chat_history)
    
    return full_response


COMMANDS = [
    "/help", "/mode", "/modes", "/models", "/setmodel", "/files", "/output", "/clear", "/exit",
    "/code", "/shell", "/payload", "/script", "/scan", "/vuln", "/web", "/dir", "/full",
    "/stealth", "/os", "/autopwn", "/fullpentest", "/enum", "/dns", "/subdomain",
    "/run", "/search", "/report", "/reporthtml", "/exec", "/tools", "/shodan", "/virus",
    "/hunter", "/crt", "/whois", "/history", "/clearhistory",
    "/session", "/resume", "/cve", "/cveupdate", "/recent",
    "/compliance", "/ioc", "/threat", "/incident", "/ir-steps", "/headers", "/vuln-db",
    "/depscan",  # Dependency vulnerability scanner
    "/escalate", "/metrics", "/backend",
    # Agent commands
    "/agent", "/workflow", "/status", "/reset", "/findings", "/summary"
]

AGENT_COMMANDS = ["/agent", "/workflow", "/status", "/reset", "/findings", "/summary"]

def get_completions():
    return COMMANDS

@app.command()
def main(
    model: str = typer.Option(None, "--model", "-m"),
    host: str = typer.Option(None, "--host"),
    list: bool = typer.Option(False, "--list", "-l"),
    nobanner: bool = typer.Option(False, "--nobanner"),
    cmd: str = typer.Option(None, "--cmd")
):
    global current_model, ollama
    
    # Banner is handled by main.py
    
    if host:
        ollama = OllamaClient(host)
    
    if not check_ollama():
        sys.exit(1)
    
    if list:
        list_models()
        return
    
    if cmd:
        intent = detect_intent(cmd)
        intent["action"] = "execute"
        intent["target"] = cmd
        auto_execute(intent)
        return
    
    current_model = model if model else select_model()
    
    print_status()
    
    # Modern command menu
    menu_lines = [
        f"[bold {CAT_SCAN}]SCANS          [/][bold {CAT_GENERATE}]GENERATION      [/][bold {CAT_ENUM}]ENUMERATION     [/][bold {CAT_UTILS}]UTILS[/]",
        f"[dim]{'─' * 16}  {'─' * 16}  {'─' * 16}  {'─' * 11}[/dim]",
        f"[{CAT_SCAN}]/scan <tgt>    [/][{CAT_GENERATE}]/code <desc>    [/][{CAT_ENUM}]/enum <tgt>      [/][{CAT_UTILS}]/tools[/]",
        f"[{CAT_SCAN}]/vuln <tgt>    [/][{CAT_GENERATE}]/shell <type>   [/][{CAT_ENUM}]/dns <dom>       [/][{CAT_UTILS}]/run <cmd>[/]",
        f"[{CAT_SCAN}]/web <tgt>     [/][{CAT_GENERATE}]/payload <tgt>  [/][{CAT_ENUM}]/subdomain <d>   [/][{CAT_UTILS}]/search <q>[/]",
        f"[{CAT_SCAN}]/full <tgt>    [/][{CAT_GENERATE}]/script <desc>  [/][{CAT_ENUM}]/autopwn <tgt>   [/][{CAT_UTILS}]/report <t>[/]",
        f"[{CAT_SCAN}]/stealth <tgt> [/][{CAT_GENERATE}]                [/][{CAT_ENUM}]/shodan <ip>     [/][{CAT_UTILS}]/cve <id>[/]",
        f"[dim]{' ' * 16}  {' ' * 16}  [{CAT_ENUM}]/virus <dom>    [/][{CAT_UTILS}]/skills[/]",
        f"[dim]{' ' * 16}  {' ' * 16}  [{CAT_ENUM}]/hunter <dom>   [/][{CAT_UTILS}]/workflows[/]",
        f"[dim]{' ' * 16}  {' ' * 16}  [{CAT_ENUM}]/crt <domain>   [/]",
        "",
        f"[dim]Type /help for full command list - /modes to switch - /exit to quit[/]",
    ]
    
    console.print(Panel(
        "\n".join(menu_lines),
        title=f"[bold {SECONDARY}]PTAI - {current_model[:30]}[/]",
        border_style=TEXT_MUTED,
        box=box.ROUNDED,
        padding=(0, 2)
    ))
    
    console.print()
    
    while True:
        try:
            current = get_current_mode()
            mode_info = get_mode_info(current)
            mode_color = mode_info.get('color', '#808080')
            user_input = console.input(f"[bold {mode_color}]{mode_info['icon']} {mode_info['name']} > [/]")
            if user_input.strip():
                chat_with_ai(user_input, current_model)
        except KeyboardInterrupt:
            console.print(f"\n[dim]{'─' * 60}[/]")
            console.print(f"[dim]Session ended. Goodbye![/]")
            break


if __name__ == "__main__":
    app()
