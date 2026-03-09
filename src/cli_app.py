import os
import sys
import re

if sys.platform == 'win32':
    os.system('chcp 65001 >nul')

import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from typing import List, Dict, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ollama_client import OllamaClient
from src.ai.prompts import SYSTEM_PROMPTS
from src.tools.security import analyze_request, check_and_log, sanitize_target, validate_command
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

app = typer.Typer(help="PTAI - Pentesting AI Tool")
console = Console()
ollama = OllamaClient()
current_model = None
chat_history = load_history()[:50]

BANNER = """
[bold #FF6B35]
██████╗ ███████╗████████╗██████╗  ██████╗ 
██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗
██████╔╝█████╗     ██║   ██████╔╝██║   ██║
██╔══██╗██╔══╝     ██║   ██╔══██╗██║   ██║
██║  ██║███████╗   ██║   ██║  ██║╚██████╔╝
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ 
[/bold #FF6B35]
[#A0A0A0]PTAI - Pentesting AI Tool[/#A0A0A0]"""


def print_banner():
    console.print(BANNER)
    current = get_current_mode()
    mode_info = get_mode_info(current)
    console.print(f"[bold]Modo:[/] {mode_info['icon']} {mode_info['name']}")
    console.print()


def check_ollama():
    if not ollama.check_connection():
        console.print("[red]✗ No se pudo conectar a Ollama[/red]")
        return False
    console.print("[green]✓ Conexión con Ollama exitosa[/green]")
    return True


def list_models():
    models = ollama.list_models()
    if not models:
        console.print("[yellow]No hay modelos disponibles[/yellow]")
        return []
    
    table = Table(title="Modelos disponibles", box=box.ROUNDED)
    table.add_column("Nombre", style="#00FF88")
    table.add_column("Tamaño", style="#FFD93D")
    for m in models:
        size_gb = m.get("size", 0) / (1024**3)
        table.add_row(m.get("name", "Unknown"), f"{size_gb:.2f} GB")
    console.print(table)
    return models


def select_model() -> str:
    models = list_models()
    if not models:
        console.print("[red]No hay modelos disponibles[/red]")
        sys.exit(1)
    console.print(f"\n[bold]Selecciona un modelo (1-{len(models)}):[/bold]")
    for i, m in enumerate(models, 1):
        console.print(f"  {i}. {m.get('name')}")
    try:
        choice = int(console.input("\n> ")) - 1
        if 0 <= choice < len(models):
            selected = models[choice].get("name", "llama3.2")
            console.print(f"[#00FF88]✓ Modelo seleccionado: {selected}[/]\n")
            return selected
    except:
        pass
    selected = models[0].get("name", "llama3.2")
    console.print(f"[#00FF88]✓ Modelo seleccionado: {selected}[/]\n")
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
    
    greetings = ['hola', 'hello', 'hey', 'hi', 'buenas', 'que tal', 'wenas', 'buenos', 'buenas']
    if any(text.strip().lower() == g or text.strip().lower().startswith(g + ' ') for g in greetings):
        intent["action"] = "greeting"
        return intent
    
    if any(w in msg_lower for w in ['escanea', 'scan', 'analiza', 'target', 'objetivo', 'mapea', 'haz un escaneo']):
        intent["action"] = "scan"
        
        if any(w in msg_lower for w in ['evasion', 'ids', 'ips', 'firewall', 'sigiloso', 'stealth', 'oculto', 'sin detected', 'indetectable']):
            intent["tool"] = "stealth"
        elif any(w in msg_lower for w in ['vuln', 'vulnerab', 'exploit', 'cve', 'vulnerabilidad']):
            intent["tool"] = "vuln"
        elif any(w in msg_lower for w in ['web', 'http', 'sitio', 'pagina', 'app', 'webapp']):
            intent["tool"] = "web"
        elif any(w in msg_lower for w in ['directorio', 'dir', 'carpeta', 'content', 'ruta']):
            intent["tool"] = "dir"
        elif any(w in msg_lower for w in ['completo', 'full', 'todo', 'profundo', 'all', 'exhaustivo']):
            intent["tool"] = "full"
        elif any(w in msg_lower for w in ['rápido', 'quick', 'basic', 'simple', 'veloz']):
            intent["tool"] = "quick"
        elif any(w in msg_lower for w in ['puerto', 'port', 'puertos especificos']):
            intent["tool"] = "custom"
        elif any(w in msg_lower for w in ['os', 'sistema operativo', 'detectar so']):
            intent["tool"] = "os"
        else:
            intent["tool"] = "quick"
    
    elif any(w in msg_lower for w in ['busca', 'search', 'exploit', 'cve', 'busca exploit', 'busca vulnerable']):
        intent["action"] = "search"
        if intent["target"]:
            intent["params"]["keyword"] = intent["target"]
        else:
            keywords = ['apache', 'nginx', 'wordpress', 'mysql', 'ssh', 'ftp', 'smb', 'redis', 'postgres', 'windows', 'linux']
            for kw in keywords:
                if kw in msg_lower:
                    intent["params"]["keyword"] = kw
                    break
    
    elif any(w in msg_lower for w in ['automático', 'autopwn', 'todo junto', 'pentest completo', 'full audit', 'todo automatico']):
        intent["action"] = "autopwn"
    
    elif any(w in msg_lower for w in ['ejecuta', 'run', 'corre', 'ejecutar', 'haz']):
        intent["action"] = "execute"
    
    elif any(w in msg_lower for w in ['genera', 'crea', 'make', 'build', 'script', 'código', 'payload', 'shell']):
        intent["action"] = "generate"
        if any(w in msg_lower for w in ['reverse', 'backdoor', 'bind']):
            intent["params"]["type"] = "shell"
        elif any(w in msg_lower for w in ['exploit', 'poc']):
            intent["params"]["type"] = "exploit"
        elif any(w in msg_lower for w in ['tool', 'herramienta', 'automation']):
            intent["params"]["type"] = "tool"
        else:
            intent["params"]["type"] = "script"
    
    elif any(w in msg_lower for w in ['reporte', 'report', 'documenta', 'informe']):
        intent["action"] = "report"
    
    elif any(w in msg_lower for w in ['archivos', 'files', 'scripts', 'generados', 'lista']):
        intent["action"] = "list_files"
    
    elif any(w in msg_lower for w in ['analiza', 'analisis', 'analyze', 'resultados']):
        intent["action"] = "analyze"
    
    elif any(w in msg_lower for w in ['fuerza bruta', 'brute', 'password', 'credencial']):
        intent["action"] = "bruteforce"
    
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
            console.print(f"[#FFD93D]🔍 Escaneo de vulnerabilidades en {target}...[/]")
            result = vuln_scan(target)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Vuln Scan - {target}", border_style="#FF4757"))
                return "Escaneo completado. ¿Analizo los resultados?"
        
        elif tool == "web":
            console.print(f"[#FFD93D]🔍 Escaneo web en {target}...[/]")
            result = web_scan(target)
            for t, res in result.items():
                if res["success"]:
                    console.print(Panel(res["output"][:2000], title=f"{t} - {target}", border_style="#FF6B35"))
            return "Escaneo web completado."
        
        elif tool == "dir":
            console.print(f"[#FFD93D]🔍 Escaneo de directorios en {target}...[/]")
            result = dir_scan(target)
            if result["success"]:
                console.print(Panel(result["output"][:2000], title=f"Dir Scan - {target}", border_style="#FF6B35"))
            return "Escaneo de directorios completado."
        
        elif tool == "full":
            console.print(f"[#FFD93D]🔍 Escaneo completo en {target}...[/]")
            result = full_scan(target)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Full Scan - {target}", border_style="#00FF88"))
            return "Escaneo completo terminado."
        
        elif tool == "stealth":
            console.print(f"[#FFD93D]🔍 Escaneo con evasion de IDS/Firewall en {target}...[/]")
            console.print(f"[#FF4757]⚠️ Usando tecnicas: fragmented, slow, source-port manipulation...[/]")
            result = execute_command(f"nmap -sS -T2 -f -g 53 --script=firewall-bypass {target}")
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Stealth Scan - {target}", border_style="#FF6B35"))
            else:
                result = execute_command(f"nmap -sS -T2 -f -p- {target}")
                if result["success"]:
                    console.print(Panel(result["output"][:3000], title=f"Stealth Scan - {target}", border_style="#FF6B35"))
                else:
                    console.print(Panel(result.get("error", "Error"), title="Error", border_style="#FF4757"))
            return "Escaneo sigiloso completado."
        
        elif tool == "os":
            console.print(f"[#FFD93D]🔍 Deteccion de SO en {target}...[/]")
            result = os_detect(target)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"OS Detect - {target}", border_style="#00FF88"))
            else:
                console.print(Panel(result.get("error", "Error"), title="Error", border_style="#FF4757"))
            return "Deteccion de SO completada."
        
        elif tool == "custom":
            ports = intent.get("ports")
            if ports:
                console.print(f"[#FFD93D]🔍 Escaneo de puertos {ports} en {target}...[/]")
                result = execute_command(f"nmap -sV -p {ports} {target}")
            else:
                console.print(f"[#FFD93D]🔍 Escaneo en {target}...[/]")
                result = quick_scan(target)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Scan - {target}", border_style="#00FF88"))
            else:
                console.print(Panel(result["error"][:1000], title="Error", border_style="#FF4757"))
            return "Escaneo completado."
        
        else:
            console.print(f"[#FFD93D]🔍 Escaneo rapido en {target}...[/]")
            result = quick_scan(target)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Quick Scan - {target}", border_style="#00FF88"))
            else:
                console.print(Panel(result["error"][:1000], title="Error", border_style="#FF4757"))
            return "Escaneo completado."
    
    elif action == "search":
        keyword = params.get("keyword") or target
        if keyword:
            console.print(f"[#FFD93D]🔍 Buscando exploits para {keyword}...[/]")
            result = search_exploits(keyword)
            if result["output"]:
                console.print(Panel(result["output"][:2500], title=f"Exploits: {keyword}", border_style="#FF6B35"))
            else:
                console.print(Panel(result["error"][:1000] if result.get("error") else "No se encontraron resultados", title="Resultado", border_style="#FF4757"))
            return "Busqueda completada."
    
    elif action == "autopwn" and target:
        console.print(f"[#FF4757]⚡ Pentest automático en {target}...[/]")
        console.print("[#FFD93D]1. Escaneo rápido...[/]")
        scan_result = quick_scan(target)
        
        console.print("[#FFD93D]2. Escaneo de vulnerabilidades...[/]")
        vuln_result = vuln_scan(target)
        
        console.print("[#FFD93D]3. Escaneo web...[/]")
        web_result = web_scan(target)
        
        console.print("[#FFD93D]4. Escaneo de directorios...[/]")
        dir_result = dir_scan(target)
        
        all_output = f"Nmap:\n{scan_result.get('output', '')}\n\nVuln:\n{vuln_result.get('output', '')}\n\nDir:\n{dir_result.get('output', '')}"
        report_path = create_quick_report(target, {"output": all_output}, "autopwn")
        console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
        return f"Pentest automático completado. Reporte en: {report_path}"
    
    elif action == "execute" and target:
        console.print(f"[#FFD93D]⚡ Ejecutando: {target}[/]")
        result = execute_command(target)
        if result["output"]:
            console.print(Panel(result["output"][:2000], title="Resultado", border_style="#00FF88"))
        if result["error"]:
            console.print(Panel(result["error"][:1000], title="Error", border_style="#FF4757"))
        return f"Código: {result['returncode']}"
    
    elif action == "generate":
        console.print("[#FFD93D]⚡ Generando código...[/]")
        return "Entendido. Describe qué tipo de código necesitas (reverse shell, script, exploit, herramienta) y lo generaré automáticamente."
    
    elif action == "report":
        if target:
            console.print(f"[#FFD93D]📄 Generando reporte para {target}...[/]")
            result = quick_scan(target)
            report_path = create_quick_report(target, result, "nmap")
            console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
            return f"Reporte generado: {report_path}"
        else:
            return "Especifica un objetivo para el reporte. Ej: 'genera reporte de 192.168.1.1'"
    
    elif action == "list_files":
        files = list_files("all")
        if not files:
            return "No hay archivos generados."
        for cat, file_list in files.items():
            if file_list:
                console.print(f"\n[#FF6B35]{cat.upper()}:[/]")
                for f in file_list:
                    console.print(f"  {f['name']} ({f['size']} bytes)")
        return None
    
    elif action == "analyze":
        if target:
            console.print(f"[#FFD93D]🔍 Analizando {target}...[/]")
            result = vuln_scan(target)
            if result["output"]:
                console.print(Panel(result["output"][:2000], title=f"Análisis - {target}", border_style="#FF6B35"))
            return "Análisis completado."
        return "Especifica qué analizar."
    
    return None


def show_help():
    help_text = f"""
[bold #FF6B35]╔══════════════════════════════════════════════════════════╗[/]
[bold #FF6B35]║         PTAI - Detección Automática de Intenciones       ║[/]
[bold #FF6B35]╚══════════════════════════════════════════════════════════╝

[#00FF88]La IA detecta automáticamente lo que necesitas:[/]

[#FFD93D]ESCANEOS:[/]
  • "escanea 192.168.1.1"           → Nmap rápido
  • "escaneo completo de google.com" → Full scan
  • "busca vulnerabilidades en X"    → Vuln scan
  • "analiza puertos 22,80,443 X"   → Puertos específicos
  • "escaneo web de miweb.com"      → Nikto + WhatWeb
  • "busca directorios en X"        → Dir scan

[#FFD93D]BÚSQUEDA:[/]
  • "busca exploits de apache"      → SearchSploit
  • "busca cve de nginx"            → Busca CVEs
  • "exploits para mysql"            → Exploit-DB

[#FFD93D]GENERACIÓN:[/]
  • "genera reverse shell python"   → Crea payload
  • "crea script de enumeración"     → Script automation
  • "make bind shell bash"          → Shell payload

[#FFD93D]AUTOMÁTICO:[/]
  • "pentest completo a X"          → Todo automático
  • "autopwn 192.168.1.1"           → Auto-explotación

[#FFD93D]REPORTES:[/]
  • "genera reporte de X"           → Crea informe
  • "documenta el escaneo"          → Reporte Markdown

[#FF6B35]COMANDOS:[/]
  /help, /files, /models, /clear, /exit

[#A0A0A0]Salida:[/] {get_output_dir()}
"""
    console.print(help_text)


def process_command(user_input: str) -> Optional[str]:
    parts = user_input.split(None, 1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    
    if cmd == "/help":
        show_help()
        return None
    elif cmd == "/mode":
        if args:
            mode = args.lower()
            if set_mode(mode):
                mode_info = get_mode_info(mode)
                console.print(f"[bold]{mode_info['icon']} Modo cambiado a: {mode_info['name']}[/]")
                console.print(f"{mode_info['description']}")
                print_banner()
                return None
            else:
                console.print("[red]Modo no válido. Modos disponibles:[/]")
                for m, info in MODES.items():
                    console.print(f"  {info['icon']} {m:12} - {info['name']}")
                return None
        else:
            current = get_current_mode()
            mode_info = get_mode_info(current)
            console.print(f"[bold]Modo actual: {mode_info['icon']} {mode_info['name']}[/]")
            console.print(f"\n[bold]Modos disponibles:[/]")
            for m, info in MODES.items():
                marker = "→" if m == current else " "
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
    elif cmd == "/files":
        files = list_files("all")
        for cat, file_list in files.items():
            if file_list:
                console.print(f"\n[#FF6B35]{cat.upper()}:[/]")
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
        console.print("[#FF6B35]¡Hasta luego! 👋[/]")
        sys.exit(0)
    elif cmd in ["/code", "/genera", "/script", "/create"]:
        if args:
            console.print(f"[#FFD93D]⚡ Generando código: {args}...[/]")
            return f"generate_code|{args}"
        console.print("[#FFD93D]⚡ Generando código...[/]")
        return "generate_code|ayúdame con scripts de pentesting"
    
    elif cmd in ["/shell", "/shells"]:
        if args:
            console.print(f"[#FFD93D]⚡ Generando shell: {args}...[/]")
            return f"generate_code|genera {args} shell para pentesting"
        console.print("[#FFD93D]⚡ Generando shell...[/]")
        return "generate_code|genera reverse shell en python"
    
    elif cmd in ["/payload", "/payloads"]:
        if args:
            console.print(f"[#FFD93D]⚡ Generando payload: {args}...[/]")
            return f"generate_code|genera payload {args} para pentesting"
        console.print("[#FFD93D]⚡ Generando payload...[/]")
        return "generate_code|genera un payload para linux"
    
    elif cmd in ["/scan", "/vuln", "/web", "/dir", "/full", "/stealth", "/os"]:
        if args:
            return f"continue_scan|{cmd}|{args}"
        return f"Uso: {cmd} <target> (ej: {cmd} 192.168.1.1)"
    
    elif cmd == "/autopwn":
        if args:
            return f"continue_autopwn|{args}"
        return "Uso: /autopwn <target> (ej: /autopwn 192.168.1.1)"
    
    elif cmd == "/fullpentest":
        if args:
            return f"continue_fullpentest|{args}"
        return "Uso: /fullpentest <target> (ej: /fullpentest 192.168.1.1)"
    
    elif cmd == "/enum":
        if args:
            console.print(f"[#FFD93D]🔍 Enumeracion completa en {args}...[/]")
            console.print("[#FFD93D]1. Escaneo de puertos...[/]")
            port_result = port_scan(args)
            console.print("[#FFD93D]2. Deteccion de SO...[/]")
            os_result = os_detect(args)
            console.print("[#FFD93D]3. Enumeracion DNS...[/]")
            dns_result = dns_enum(args)
            console.print("[#FFD93D]4. Enumeracion de subdominios...[/]")
            sub_result = subdomain_enum(args)
            
            all_output = f"Port Scan:\n{port_result.get('output', '')}\n\nOS Detect:\n{os_result.get('output', '')}\n\nDNS Enum:\n{dns_result.get('output', '')}\n\nSubdomain Enum:\n{sub_result.get('output', '')}"
            
            if port_result["success"]:
                console.print(Panel(port_result["output"][:2000], title=f"Ports - {args}", border_style="#00FF88"))
            if os_result["success"]:
                console.print(Panel(os_result["output"][:2000], title=f"OS - {args}", border_style="#00FF88"))
            if dns_result["success"]:
                console.print(Panel(dns_result["output"][:2000], title=f"DNS - {args}", border_style="#FF6B35"))
            if sub_result["success"]:
                console.print(Panel(sub_result["output"][:2000], title=f"Subdomains - {args}", border_style="#FF6B35"))
            
            report_path = create_quick_report(args, {"output": all_output}, "enum")
            console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
            return f"Enumeracion completada. Reporte: {report_path}"
        return "Uso: /enum <target> (ej: /enum 192.168.1.1)"
    
    elif cmd == "/dns":
        if args:
            console.print(f"[#FFD93D]🔍 Enumeracion DNS en {args}...[/]")
            result = dns_enum(args)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"DNS Enum - {args}", border_style="#00FF88"))
            else:
                console.print(Panel(result.get("error", "Error"), title="Error", border_style="#FF4757"))
            return None
        return "Uso: /dns <domain> (ej: /dns ejemplo.com)"
    
    elif cmd == "/subdomain":
        if args:
            console.print(f"[#FFD93D]🔍 Buscando subdominios en {args}...[/]")
            result = subdomain_enum(args)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Subdomains - {args}", border_style="#00FF88"))
            else:
                console.print(Panel(result.get("error", "Error"), title="Error", border_style="#FF4757"))
            return None
        return "Uso: /subdomain <domain> (ej: /subdomain ejemplo.com)"
    
    elif cmd == "/run":
        if args:
            is_valid, error_msg = validate_command(args)
            if not is_valid:
                console.print(f"[red]⚠️ Comando bloqueado: {error_msg}[/]")
                return "Comando no permitido."
            console.print(f"[#FFD93D]⚡ Ejecutando: {args}[/]")
            result = execute_command(args)
            if result["output"]:
                console.print(Panel(result["output"][:2500], title="Output", border_style="#00FF88"))
            if result.get("error") and result["returncode"] != 0:
                console.print(Panel(result["error"][:1000], title="Error", border_style="#FF4757"))
            return f"Codigo: {result['returncode']}"
        return "Uso: /run <comando>"
    
    elif cmd == "/search" or cmd == "/exploit":
        if args:
            console.print(f"[#FFD93D]🔍 Buscando exploits: {args}[/]")
            result = search_exploits(args)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"Exploits for: {args}", border_style="#FF6B35"))
            else:
                console.print(Panel(result.get("error", "No se encontraron resultados"), title="Error", border_style="#FF4757"))
            return None
        return "Uso: /search <term>"
    
    elif cmd == "/report":
        if args:
            console.print(f"[#FFD93D]⚡ Generando reporte de {args}...[/]")
            result = quick_scan(args)
            report_path = create_quick_report(args, result, "nmap")
            console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
            return None
        return "Uso: /report <target>"
    
    elif cmd == "/exec":
        if args:
            parts = args.split(None, 1)
            tool_name = parts[0]
            tool_args = parts[1] if len(parts) > 1 else ""
            console.print(f"[#FFD93D]⚡ Ejecutando {tool_name}...[/]")
            from src.tools.pentest import run_tool
            result = run_tool(tool_name, tool_args)
            if result["success"]:
                console.print(Panel(result["output"][:3000], title=f"{tool_name} Output", border_style="#00FF88"))
            else:
                console.print(Panel(result.get("error", "Error ejecutando"), title="Error", border_style="#FF4757"))
            return None
        return "Uso: /exec <tool> <args> (ej: /exec nmap -sV 192.168.1.1)"
    
    elif cmd == "/tools":
        from src.tools.pentest import get_available_tools
        tools = get_available_tools()
        if tools:
            for cat, tool_list in tools.items():
                console.print(f"[#FF6B35]{cat.upper()}:[/] {', '.join(tool_list)}")
        else:
            console.print("[yellow]No hay herramientas disponibles (instala Kali Linux o las herramientas manualmente)[/]")
        return None
    
    elif cmd == "/shodan":
        if args:
            console.print(f"[#FFD93D]🔍 Consultando Shodan: {args}[/]")
            result = shodan_scan(args)
            if result["success"]:
                console.print(Panel(result["output"], title=f"Shodan - {args}", border_style="#00FF88"))
            else:
                console.print(Panel(result["error"], title="Error", border_style="#FF4757"))
            return None
        return "Uso: /shodan <IP>"
    
    elif cmd == "/virus":
        if args:
            console.print(f"[#FFD93D]🔍 Escaneando en VirusTotal: {args}[/]")
            result = virustotal_scan(args)
            if result["success"]:
                console.print(Panel(result["output"], title=f"VirusTotal - {args}", border_style="#00FF88"))
            else:
                console.print(Panel(result["error"], title="Error", border_style="#FF4757"))
            return None
        return "Uso: /virus <domain>"
    
    elif cmd == "/hunter":
        if args:
            console.print(f"[#FFD93D]🔍 Buscando emails: {args}[/]")
            result = hunter_lookup(args)
            if result["success"]:
                console.print(Panel(result["output"], title=f"Hunter - {args}", border_style="#00FF88"))
            else:
                console.print(Panel(result["error"], title="Error", border_style="#FF4757"))
            return None
        return "Uso: /hunter <domain>"
    
    elif cmd == "/crt":
        if args:
            console.print(f"[#FFD93D]🔍 Buscando certificados: {args}[/]")
            result = crt_sh_lookup(args)
            if result["success"]:
                console.print(Panel(result["output"], title=f"CRT.SH - {args}", border_style="#00FF88"))
            else:
                console.print(Panel(result["error"], title="Error", border_style="#FF4757"))
            return None
        return "Uso: /crt <domain>"
    
    elif cmd == "/whois":
        if args:
            console.print(f"[#FFD93D]🔍 Whois: {args}[/]")
            result = whois_lookup(args)
            if result["success"]:
                console.print(Panel(result["output"], title=f"Whois - {args}", border_style="#00FF88"))
            else:
                console.print(Panel(result["error"], title="Error", border_style="#FF4757"))
            return None
        return "Uso: /whois <domain>"
    
    elif cmd == "/history":
        hist = load_history()
        if hist:
            console.print(f"[#FF6B35]Historial ({len(hist)} mensajes):[/]")
            for msg in hist[-10:]:
                role = "👤" if msg["role"] == "user" else "🤖"
                console.print(f"{role} {msg['role']}: {msg['content'][:50]}...")
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
            console.print(f"[green]✓ Sesión creada: {session_name}[/]")
            return f"Usa /resume {session_name} para continuar"
        sessions = list_sessions()
        if sessions:
            console.print(f"[#FF6B35]Sesiones guardadas ({len(sessions)}):[/]")
            for s in sessions[:10]:
                console.print(f"  {s['name']} - {s.get('created', '')[:10]} - {len(s.get('targets', []))} targets")
        else:
            console.print("[yellow]No hay sesiones[/]")
        return None
    
    elif cmd == "/resume":
        if args:
            session_data = load_session(args)
            if session_data:
                console.print(f"[green]✓ Sesión cargada: {args}[/]")
                console.print(f"Targets: {', '.join(session_data.get('targets', []))}")
            else:
                console.print(f"[red]Sesión no encontrada: {args}[/]")
        else:
            console.print("[yellow]Uso: /resume <nombre>[/]")
        return None
    
    elif cmd == "/cve":
        if args:
            cve_id = args.strip().upper()
            if not cve_id.startswith("CVE-"):
                results = search_by_keyword(args)
                if results:
                    console.print(f"[#FF6B35]Resultados para '{args}' ({len(results)}):[/]")
                    for cve in results[:10]:
                        console.print(f"  {cve['cveID']} - {cve['vendorProject']} - {cve['product']}")
                else:
                    console.print("[yellow]No se encontraron resultados[/]")
            else:
                cve = search_cve(cve_id)
                if cve:
                    console.print(Panel(format_cve(cve), title=f"CVE: {cve_id}", border_style="#FF6B35"))
                else:
                    console.print(f"[yellow]CVE no encontrado: {cve_id}[/]")
        else:
            stats = get_stats()
            console.print(f"[#FF6B35]CISA KEV Database:[/]")
            console.print(f"  Total CVEs: {stats.get('total', 0)}")
        return None
    
    elif cmd == "/cveupdate":
        console.print("[#FFD93D]Descargando CISA KEV...[/]")
        if download_cisa_kev(force=True):
            console.print("[green]✓ Base de datos CVE actualizada[/]")
        else:
            console.print("[red]✗ Error al descargar[/]")
        return None
    
    elif cmd == "/recent":
        exploits = get_recent_exploits(30)
        console.print(f"[#FF6B35]Explotados recientemente (últimos 30 días):[/]")
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
                assessment_type="Escaneo automático",
                format="html"
            )
            console.print(f"[#00FF88]✓ Reporte HTML: {report_path}[/]")
        else:
            console.print("[yellow]Uso: /reporthtml <target>[/]")
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
    ("instalado", "tool", "nmap", "python", "git"): lambda t: check_tool(t or "nmap"),
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
            console.print(Panel(result["output"][:3000], title=f"{tool.upper()} - {target}", border_style="#00FF88"))
        return None
    elif cmd_result and cmd_result.startswith("continue_autopwn|"):
        target = cmd_result.split("|")[1]
        console.print(f"[#FF4757]⚡ Pentest automático en {target}...[/]")
        scan_result = quick_scan(target)
        vuln_result = vuln_scan(target)
        web_result = web_scan(target)
        all_output = f"Nmap:\n{scan_result.get('output', '')}\n\nVuln:\n{vuln_result.get('output', '')}"
        report_path = create_quick_report(target, {"output": all_output}, "autopwn")
        console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
        return f"Pentest completado. Reporte en: {report_path}"
    elif cmd_result and cmd_result.startswith("continue_fullpentest|"):
        target = cmd_result.split("|")[1]
        console.print(f"[#FF4757]⚡ PENTEST COMPLETO en {target}...[/]")
        
        console.print("[#FFD93D]1. Escaneo rapido...[/]")
        scan_result = quick_scan(target)
        
        console.print("[#FFD93D]2. Escaneo completo de puertos...[/]")
        full_result = full_scan(target)
        
        console.print("[#FFD93D]3. Deteccion de SO...[/]")
        os_result = os_detect(target)
        
        console.print("[#FFD93D]4. Escaneo de vulnerabilidades...[/]")
        vuln_result = vuln_scan(target)
        
        console.print("[#FFD93D]5. Escaneo web...[/]")
        web_result = web_scan(target)
        
        console.print("[#FFD93D]6. Escaneo de directorios...[/]")
        dir_result = dir_scan(target)
        
        console.print("[#FFD93D]7. Enumeracion DNS...[/]")
        dns_result = dns_enum(target)
        
        console.print("[#FFD93D]8. Enumeracion de subdominios...[/]")
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
        console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
        return f"Pentest COMPLETO terminado. Reporte en: {report_path}"
    elif cmd_result and cmd_result.startswith("generate_code|"):
        prompt = cmd_result.split("|")[1]
        console.print(f"[#FFD93D]⚡ Generando: {prompt}...[/]")
        
        use_model: str = model
        restricted_terms = ['keylog', 'malware', 'ransomware', 'trojan', 'virus', 'backdoor', 'spyware']
        if any(term in prompt.lower() for term in restricted_terms):
            available = ollama.list_models()
            for m in available:
                name = m.get('name') or ''
                if 'dolphin' in name.lower() or 'mixtral' in name.lower():
                    use_model = name
                    console.print(f"[#FFD93D]⚡ Usando modelo: {use_model}[/]")
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
        
        console.print("[#FFD93D]⚡ Generando código...[/]")
        
        import time
        start_time = time.time()
        response = []
        
        try:
            for chunk in ollama.chat(use_model, messages):
                response.append(chunk)
        except Exception as e:
            console.print(f"[#FF4757]Error en generación: {str(e)}[/]")
            return f"Error: {str(e)}"
        
        elapsed = int(time.time() - start_time)
        full_response = "".join(response)
        char_count = len(full_response)
        
        console.print(f"\n[#00FF88]✓ Completado en {elapsed}s [{char_count} chars][/]")
        
        if full_response.strip():
            sys.stdout.write(full_response)
            sys.stdout.flush()
            console.print(Panel(full_response[:5000], title="Respuesta IA", border_style="#00FF88"))
        
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
                console.print("[yellow]⚠ Código muy corto para guardar, mostrándolo directamente:[/]")
                console.print(Panel(code_match.strip()[:2000], title="Código generado", border_style="#00FF88"))
            else:
                ext = f".{detected_lang}"
                stop_words = ['un', 'una', 'para', 'de', 'el', 'la', 'creame', 'genera', 'make', 'me', 'un', 'un', 'un', 'codigo', 'script']
                name_words = [w for w in prompt.split() if w.lower() not in stop_words and len(w) > 2]
                name = "_".join(name_words[:3]) if name_words else "script"
                filename = f"{name}{ext}"
                
                from src.tools.system import save_code
                filepath = save_code(code_match, filename, "scripts")
                console.print(f"[#00FF88]✓ Código guardado en: {filepath}[/]")
        
        return None
    elif cmd_result:
        return cmd_result
    elif cmd_result is None:
        return None
    
    intent = detect_intent(message)
    auto_result = auto_execute(intent)
    if auto_result:
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

¡HAZ, NO DIGAS QUE HARÁS!"""

    messages = [
        {"role": "system", "content": system_prompt},
        *chat_history[-8:],
        {"role": "user", "content": message}
    ]
    
    import time
    start_time = time.time()
    response = []
    
    console.print("[#FFD93D]⚡ Procesando...[/]")
    
    for chunk in ollama.chat(model, messages):
        response.append(chunk)
        print(chunk, end="", flush=True)
    
    full_response = "".join(response)
    
    clean_response, func_results = execute_function_call(full_response)
    
    if func_results:
        console.print(Panel("\n".join(func_results), title="[green]Resultados de funciones ejecutadas[/]", border_style="#00FF88"))
        messages.append({"role": "assistant", "content": clean_response})
        messages.append({"role": "user", "content": f"Resultados de las funciones: {func_results}"})
        
        response = []
        console.print("[#FFD93D]⚡ Procesando resultados...[/]")
        
        for chunk in ollama.chat(model, messages):
            response.append(chunk)
            print(chunk, end="", flush=True)
        
        full_response = "".join(response)
    
    elapsed = int(time.time() - start_time)
    char_count = len(full_response)
    console.print(f"[#00FF88]✓ Completado en {elapsed}s ({char_count} chars)[/]")
    print()
    
    chat_history.append({"role": "user", "content": message})
    chat_history.append({"role": "assistant", "content": full_response})
    
    save_history(chat_history)
    
    return full_response


COMMANDS = [
    "/help", "/mode", "/modes", "/models", "/setmodel", "/files", "/output", "/clear", "/exit",
    "/code", "/shell", "/payload", "/scan", "/vuln", "/web", "/dir", "/full",
    "/stealth", "/os", "/autopwn", "/fullpentest", "/enum", "/dns", "/subdomain",
    "/run", "/search", "/report", "/reporthtml", "/exec", "/tools", "/shodan", "/virus",
    "/hunter", "/crt", "/whois", "/history", "/clearhistory",
    "/session", "/resume", "/cve", "/cveupdate", "/recent"
]

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
    
    if not nobanner:
        print_banner()
    
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
    
    console.print(Panel(
        f"[#00FF88]Modelo:[/] {current_model}\n"
        f"[#A0A0A0]Salida:[/] {get_output_dir()}\n\n"
        f"[#FFD93D]╔════════════════════════════════════════╗[/]\n"
        f"[#FFD93D]║           COMANDOS RÁPIDOS            ║[/]\n"
        f"[#FFD93D]╚════════════════════════════════════════╝[/]\n\n"
        f"[#00FF88]Generación:[/]\n"
        f"  /code <tipo>       - Generar codigo\n"
        f"  /shell <tipo>      - Generar shells\n"
        f"  /payload <tipo>    - Generar payloads\n\n"
        f"[#00FF88]Escaneos:[/]\n"
        f"  /scan <target>     - Escaneo rapido (nmap)\n"
        f"  /vuln <target>    - Vulnerabilidades\n"
        f"  /web <target>     - Escaneo web\n"
        f"  /full <target>    - Escaneo completo\n"
        f"  /stealth <target> - Escaneo evasion\n\n"
        f"[#00FF88]Enumeracion:[/]\n"
        f"  /enum <target>    - Enumeracion completa\n"
        f"  /dns <target>    - Enumeracion DNS\n"
        f"  /subdomain <target> - Subdominios\n\n"
        f"[#00FF88]Pentest:[/]\n"
        f"  /autopwn <target> - Pentest automatico\n"
        f"  /fullpentest <target> - Pentest completo\n\n"
        f"[#00FF88]APIs (configurar claves):[/]\n"
        f"  /shodan <IP>      - Shodan lookup\n"
        f"  /virus <domain>   - VirusTotal scan\n"
        f"  /hunter <domain>  - Buscar emails\n"
        f"  /crt <domain>     - Certificados SSL\n"
        f"  /whois <domain>   - Whois lookup\n\n"
        f"[#00FF88]Sistema:[/]\n"
        f"  /run <cmd>        - Comando directo\n"
        f"  /exec <tool> args - Ejecutar herramienta\n"
        f"  /search <term>    - Buscar exploits\n"
        f"  /tools            - Herramientas disponibles\n"
        f"  /history          - Ver historial\n"
        f"  /files            - Archivos generados",
        title="PTAI - Pentesting AI Tool", border_style="#FF6B35"
    ))
    
    while True:
        try:
            user_input = console.input("[#FF6B35]»[/] ")
            if user_input.strip():
                chat_with_ai(user_input, current_model)
        except KeyboardInterrupt:
            console.print("\n[#FF6B35]¡Hasta luego![/]")
            break


if __name__ == "__main__":
    app()
