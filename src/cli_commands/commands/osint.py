from typing import Optional
from src.tools.apis import (
    shodan_scan, virustotal_scan, hunter_lookup,
    crt_sh_lookup, whois_lookup
)
from rich.panel import Panel


def handle_shodan(ip: str, console) -> Optional[str]:
    console.print(f"[#FFD93D]🔍 Consultando Shodan: {ip}[/]")
    result = shodan_scan(ip)
    if result.get("success"):
        console.print(Panel(result["output"], title=f"Shodan - {ip}", border_style="#00FF88"))
    else:
        console.print(Panel(result["error"], title="Error", border_style="#FF4757"))
    return None


def handle_virustotal(domain: str, console) -> Optional[str]:
    console.print(f"[#FFD93D]🔍 Escaneando en VirusTotal: {domain}[/]")
    result = virustotal_scan(domain)
    if result.get("success"):
        console.print(Panel(result["output"], title=f"VirusTotal - {domain}", border_style="#00FF88"))
    else:
        console.print(Panel(result["error"], title="Error", border_style="#FF4757"))
    return None


def handle_hunter(domain: str, console) -> Optional[str]:
    console.print(f"[#FFD93D]🔍 Buscando emails: {domain}[/]")
    result = hunter_lookup(domain)
    if result.get("success"):
        console.print(Panel(result["output"], title=f"Hunter - {domain}", border_style="#00FF88"))
    else:
        console.print(Panel(result["error"], title="Error", border_style="#FF4757"))
    return None


def handle_crt(domain: str, console) -> Optional[str]:
    console.print(f"[#FFD93D]🔍 Buscando certificados: {domain}[/]")
    result = crt_sh_lookup(domain)
    if result.get("success"):
        console.print(Panel(result["output"], title=f"CRT.SH - {domain}", border_style="#00FF88"))
    else:
        console.print(Panel(result["error"], title="Error", border_style="#FF4757"))
    return None


def handle_whois(domain: str, console) -> Optional[str]:
    console.print(f"[#FFD93D]🔍 Whois: {domain}[/]")
    result = whois_lookup(domain)
    if result.get("success"):
        console.print(Panel(result["output"], title=f"Whois - {domain}", border_style="#00FF88"))
    else:
        console.print(Panel(result["error"], title="Error", border_style="#FF4757"))
    return None
