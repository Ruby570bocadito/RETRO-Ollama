from typing import Optional
from src.tools.apis import (
    shodan_scan, virustotal_scan, hunter_lookup,
    crt_sh_lookup, whois_lookup
)
from rich.panel import Panel
from src.cli_theme import SUCCESS, ERROR, ACCENT

def handle_shodan(ip: str, console) -> Optional[str]:
    console.print(f"[{ACCENT}]> Consultando Shodan: {ip}[/]")
    result = shodan_scan(ip)
    if result.get("success"):
        console.print(Panel(result["output"], title=f"Shodan - {ip}", border_style=SUCCESS))
    else:
        console.print(Panel(result["error"], title="Error", border_style=ERROR))
    return None


def handle_virustotal(domain: str, console) -> Optional[str]:
    console.print(f"[{ACCENT}]> Escaneando en VirusTotal: {domain}[/]")
    result = virustotal_scan(domain)
    if result.get("success"):
        console.print(Panel(result["output"], title=f"VirusTotal - {domain}", border_style=SUCCESS))
    else:
        console.print(Panel(result["error"], title="Error", border_style=ERROR))
    return None


def handle_hunter(domain: str, console) -> Optional[str]:
    console.print(f"[{ACCENT}]> Buscando emails: {domain}[/]")
    result = hunter_lookup(domain)
    if result.get("success"):
        console.print(Panel(result["output"], title=f"Hunter - {domain}", border_style=SUCCESS))
    else:
        console.print(Panel(result["error"], title="Error", border_style=ERROR))
    return None


def handle_crt(domain: str, console) -> Optional[str]:
    console.print(f"[{ACCENT}]> Buscando certificados: {domain}[/]")
    result = crt_sh_lookup(domain)
    if result.get("success"):
        console.print(Panel(result["output"], title=f"CRT.SH - {domain}", border_style=SUCCESS))
    else:
        console.print(Panel(result["error"], title="Error", border_style=ERROR))
    return None


def handle_whois(domain: str, console) -> Optional[str]:
    console.print(f"[{ACCENT}]> Whois: {domain}[/]")
    result = whois_lookup(domain)
    if result.get("success"):
        console.print(Panel(result["output"], title=f"Whois - {domain}", border_style=SUCCESS))
    else:
        console.print(Panel(result["error"], title="Error", border_style=ERROR))
    return None
