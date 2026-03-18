from typing import Dict, Optional, List
from src.tools.pentest import (
    quick_scan, full_scan, vuln_scan, web_scan, dir_scan,
    stealth_scan, port_scan, os_detect, search_exploits, aggressive_scan,
    get_available_tools, dns_enum, subdomain_enum, run_tool
)
from src.tools.system import execute_command
from src.tools.security import sanitize_target, validate_command
from src.reports.generator import create_quick_report
from rich.panel import Panel


def handle_scan(tool: str, target: str, console) -> Optional[str]:
    sanitized = sanitize_target(target) if target else None
    if not sanitized:
        return "Target inválido"
    target = sanitized
    
    if tool == "scan":
        console.print(f"[#FFD93D]🔍 Escaneo rápido en {target}...[/]")
        result = quick_scan(target)
    elif tool == "vuln":
        console.print(f"[#FFD93D]🔍 Escaneo de vulnerabilidades en {target}...[/]")
        result = vuln_scan(target)
    elif tool == "web":
        console.print(f"[#FFD93D]🔍 Escaneo web en {target}...[/]")
        result = web_scan(target)
    elif tool == "dir":
        console.print(f"[#FFD93D]🔍 Escaneo de directorios en {target}...[/]")
        result = dir_scan(target)
    elif tool == "full":
        console.print(f"[#FFD93D]🔍 Escaneo completo en {target}...[/]")
        result = full_scan(target)
    elif tool == "stealth":
        console.print(f"[#FFD93D]🔍 Escaneo con evasión en {target}...[/]")
        result = stealth_scan(target)
    elif tool == "os":
        console.print(f"[#FFD93D]🔍 Detección de SO en {target}...[/]")
        result = os_detect(target)
    else:
        result = quick_scan(target)
    
    if result.get("success"):
        console.print(Panel(result["output"][:3000], title=f"{tool.upper()} - {target}", border_style="#00FF88"))
    else:
        console.print(Panel(result.get("error", "Error")[:1000], title="Error", border_style="#FF4757"))
    
    return "Escaneo completado."


def handle_autopwn(target: str, console) -> str:
    sanitized = sanitize_target(target)
    if not sanitized:
        return "Target inválido"
    target = sanitized
    
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
    return f"Pentest completado. Reporte en: {report_path}"


def handle_fullpentest(target: str, console) -> str:
    sanitized = sanitize_target(target)
    if not sanitized:
        return "Target inválido"
    target = sanitized
    
    console.print(f"[#FF4757]⚡ PENTEST COMPLETO en {target}...[/]")
    
    steps = [
        ("Escaneo rápido", quick_scan),
        ("Escaneo completo", full_scan),
        ("Detección SO", os_detect),
        ("Vulnerabilidades", vuln_scan),
        ("Escaneo web", web_scan),
        ("Directorios", dir_scan),
        ("DNS Enum", dns_enum),
        ("Subdominios", subdomain_enum),
    ]
    
    all_output = f"=== PENTEST COMPLETO - {target} ===\n\n"
    
    for i, (name, func) in enumerate(steps, 1):
        console.print(f"[#FFD93D]{i}. {name}...[/]")
        result = func(target)
        all_output += f"[{name}]\n{result.get('output', '')}\n\n"
    
    report_path = create_quick_report(target, {"output": all_output}, "fullpentest")
    console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
    return f"Pentest COMPLETO terminado. Reporte en: {report_path}"


def handle_enum(target: str, console) -> Optional[str]:
    sanitized = sanitize_target(target)
    if not sanitized:
        return "Target inválido"
    target = sanitized
    
    console.print(f"[#FFD93D]🔍 Enumeración completa en {target}...[/]")
    
    results = {
        "Ports": port_scan(target),
        "OS": os_detect(target),
        "DNS": dns_enum(target),
        "Subdomains": subdomain_enum(target),
    }
    
    all_output = ""
    for name, result in results.items():
        if result.get("success"):
            console.print(Panel(result["output"][:2000], title=f"{name} - {target}", border_style="#00FF88"))
        all_output += f"{name}:\n{result.get('output', '')}\n\n"
    
    report_path = create_quick_report(target, {"output": all_output}, "enum")
    console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
    return f"Enumeración completada. Reporte: {report_path}"


def handle_exec(tool_name: str, tool_args: str, console) -> Optional[str]:
    console.print(f"[#FFD93D]⚡ Ejecutando {tool_name}...[/]")
    result = run_tool(tool_name, tool_args)
    if result.get("success"):
        console.print(Panel(result["output"][:3000], title=f"{tool_name} Output", border_style="#00FF88"))
    else:
        console.print(Panel(result.get("error", "Error ejecutando"), title="Error", border_style="#FF4757"))
    return None


def handle_run(command: str, console) -> Optional[str]:
    is_valid, error_msg = validate_command(command)
    if not is_valid:
        console.print(f"[red]⚠️ Comando bloqueado: {error_msg}[/]")
        return "Comando no permitido."
    
    console.print(f"[#FFD93D]⚡ Ejecutando: {command}[/]")
    result = execute_command(command)
    
    if result.get("output"):
        console.print(Panel(result["output"][:2500], title="Output", border_style="#00FF88"))
    if result.get("error") and result["returncode"] != 0:
        console.print(Panel(result["error"][:1000], title="Error", border_style="#FF4757"))
    
    return f"Código: {result['returncode']}"


def handle_search(term: str, console) -> Optional[str]:
    console.print(f"[#FFD93D]🔍 Buscando exploits: {term}[/]")
    result = search_exploits(term)
    
    if result.get("success"):
        console.print(Panel(result["output"][:3000], title=f"Exploits for: {term}", border_style="#FF6B35"))
    else:
        console.print(Panel(result.get("error", "No se encontraron resultados"), title="Error", border_style="#FF4757"))
    return None


def handle_tools(console):
    tools = get_available_tools()
    if tools:
        for cat, tool_list in tools.items():
            console.print(f"[#FF6B35]{cat.upper()}:[/] {', '.join(tool_list)}")
    else:
        console.print("[yellow]No hay herramientas disponibles[/]")
    return None
