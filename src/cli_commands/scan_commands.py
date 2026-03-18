import sys
import os
from rich.console import Console
from rich.panel import Panel

# Ensure src is in path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.pentest import (
    quick_scan, full_scan, vuln_scan, web_scan, dir_scan,
    stealth_scan, port_scan, os_detect, search_exploits, aggressive_scan,
    dns_enum, subdomain_enum
)
from src.reports.generator import create_quick_report

console = Console()

class ScanCommands:
    @staticmethod
    def handle_scan(cmd: str, args: str) -> str:
        """Handle scan commands: /scan, /vuln, /web, /dir, /full, /stealth, /os"""
        if not args:
            return f"Uso: {cmd} <target> (ej: {cmd} 192.168.1.1)"
        
        target = args.strip()
        
        # Map command to function
        scan_func_map = {
            "/scan": quick_scan,
            "/vuln": vuln_scan,
            "/web": web_scan,
            "/dir": dir_scan,
            "/full": full_scan,
            "/os": os_detect,
        }
        
        # Handle stealth separately as it has custom logic
        if cmd == "/stealth":
            console.print(f"[#FFD93D]🔍 Escaneo con evasion de IDS/Firewall en {target}...[/]")
            console.print(f"[#FF4757]⚠️ Usando tecnicas: fragmented, slow, source-port manipulation...[/]")
            result = stealth_scan(target)
            
            if result.get("success"):
                console.print(Panel(result["output"][:3000], title=f"Stealth Scan - {target}", border_style="#FF6B35"))
            else:
                console.print(Panel(result.get("error", "Error"), title="Error", border_style="#FF4757"))
            return "Escaneo sigiloso completado."
        
        # Execute standard scan
        if cmd in scan_func_map:
            console.print(f"[#FFD93D]🔍 Ejecutando {cmd} en {target}...[/]")
            result = scan_func_map[cmd](target)
            
            if result.get("success"):
                border_style = "#00FF88" if cmd in ["/scan", "/full", "/os"] else "#FF6B35"
                console.print(Panel(result["output"][:3000], title=f"{cmd} - {target}", border_style=border_style))
            else:
                console.print(Panel(result.get("error", "Error"), title="Error", border_style="#FF4757"))
            
            return f"Escaneo completado: {cmd}"
        
        return f"Comando no reconocido: {cmd}"

    @staticmethod
    def handle_enum(args: str) -> str:
        """Handle /enum command"""
        if not args:
            return "Uso: /enum <target> (ej: /enum 192.168.1.1)"
        
        target = args.strip()
        console.print(f"[#FFD93D]🔍 Enumeracion completa en {target}...[/]")
        
        steps = [
            ("1. Escaneo de puertos...", port_scan, "Ports"),
            ("2. Deteccion de SO...", os_detect, "OS"),
            ("3. Enumeracion DNS...", dns_enum, "DNS"),
            ("4. Enumeracion de subdominios...", subdomain_enum, "Subdomains")
        ]
        
        all_outputs = []
        
        for step_desc, func, title in steps:
            console.print(f"[#FFD93D]{step_desc}[/]")
            result = func(target)
            if result.get("success"):
                border_style = "#00FF88" if title in ["Ports", "OS"] else "#FF6B35"
                console.print(Panel(result["output"][:2000], title=f"{title} - {target}", border_style=border_style))
                all_outputs.append(f"{title}:\n{result.get('output', '')}\n")
            else:
                all_outputs.append(f"{title}: Error\n")
        
        full_output = "\n".join(all_outputs)
        report_path = create_quick_report(target, {"output": full_output}, "enum")
        console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
        return f"Enumeracion completada. Reporte: {report_path}"

    @staticmethod
    def handle_autopwn(args: str) -> str:
        """Handle /autopwn command"""
        if not args:
            return "Uso: /autopwn <target> (ej: /autopwn 192.168.1.1)"
        
        target = args.strip()
        console.print(f"[#FF4757]⚡ Pentest automático en {target}...[/]")
        
        steps = [
            ("1. Escaneo rápido...", quick_scan),
            ("2. Escaneo de vulnerabilidades...", vuln_scan),
            ("3. Escaneo web...", web_scan),
            ("4. Escaneo de directorios...", dir_scan),
        ]
        
        outputs = []
        
        for step_desc, func in steps:
            console.print(f"[#FFD93D]{step_desc}[/]")
            result = func(target)
            if result.get("success"):
                outputs.append(f"{step_desc.split(' ')[1]}:\n{result.get('output', '')}\n")
        
        full_output = "\n".join(outputs)
        report_path = create_quick_report(target, {"output": full_output}, "autopwn")
        console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
        return f"Pentest automático completado. Reporte en: {report_path}"

    @staticmethod
    def handle_fullpentest(args: str) -> str:
        """Handle /fullpentest command"""
        if not args:
            return "Uso: /fullpentest <target> (ej: /fullpentest 192.168.1.1)"
        
        target = args.strip()
        console.print(f"[#FF4757]⚡ PENTEST COMPLETO en {target}...[/]")
        
        steps = [
            ("1. Escaneo rapido...", quick_scan),
            ("2. Escaneo completo de puertos...", full_scan),
            ("3. Deteccion de SO...", os_detect),
            ("4. Escaneo de vulnerabilidades...", vuln_scan),
            ("5. Escaneo web...", web_scan),
            ("6. Escaneo de directorios...", dir_scan),
            ("7. Enumeracion DNS...", dns_enum),
            ("8. Enumeracion de subdominios...", subdomain_enum),
        ]
        
        outputs = []
        
        for step_desc, func in steps:
            console.print(f"[#FFD93D]{step_desc}[/]")
            result = func(target)
            if result.get("success"):
                outputs.append(f"{step_desc.split(' ')[1]}:\n{result.get('output', '')}\n")
        
        all_output = f"""=== PENTEST COMPLETO - {target} ===

""" + "\n".join(outputs)
        
        report_path = create_quick_report(target, {"output": all_output}, "fullpentest")
        console.print(f"[#00FF88]✓ Reporte: {report_path}[/]")
        return f"Pentest completo completado. Reporte en: {report_path}"
