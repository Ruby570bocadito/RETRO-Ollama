import requests
import os
from typing import Dict, Optional, List

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")


def shodan_scan(ip: str) -> Dict:
    if not SHODAN_API_KEY:
        return {"success": False, "error": "SHODAN_API_KEY no configurada", "output": ""}
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": SHODAN_API_KEY}
        r = requests.get(url, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            output = f"""
=== SHODAN - {ip} ===
ISP: {data.get('isp', 'N/A')}
OS: {data.get('os', 'N/A')}
Ports: {data.get('ports', [])}
Hostnames: {data.get('hostnames', [])}
Vulns: {data.get('vulns', [])}
            """
            return {"success": True, "output": output, "error": ""}
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "output": ""}


def virustotal_scan(domain: str) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {"success": False, "error": "VIRUSTOTAL_API_KEY no configurada", "output": ""}
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            output = f"""
=== VIRUSTOTAL - {domain} ===
Malicious: {stats.get('malicious', 0)}
Suspicious: {stats.get('suspicious', 0)}
Harmless: {stats.get('undetected', 0)}
            """
            return {"success": True, "output": output, "error": ""}
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "output": ""}


def hunter_lookup(domain: str) -> Dict:
    if not HUNTER_API_KEY:
        return {"success": False, "error": "HUNTER_API_KEY no configurada", "output": ""}
    
    try:
        url = f"https://api.hunter.io/v2/domain-search"
        params = {"domain": domain, "api_key": HUNTER_API_KEY}
        r = requests.get(url, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            emails = data.get("data", {}).get("emails", [])[:5]
            output = f"=== HUNTER - {domain} ===\n"
            for e in emails:
                output += f"{e.get('email')} - {e.get('type')}\n"
            return {"success": True, "output": output, "error": ""}
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "output": ""}


def crt_sh_lookup(domain: str) -> Dict:
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()[:20]
            output = f"=== CRT.SH - {domain} ===\n"
            for cert in data:
                output += f"{cert.get('common_name')} - {cert.get('not_after')[:10]}\n"
            return {"success": True, "output": output, "error": ""}
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "output": ""}


def whois_lookup(domain: str) -> Dict:
    try:
        url = f"https://whois.freeaiapi.xyz/api?domain={domain}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return {"success": True, "output": r.text[:2000], "error": ""}
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "output": ""}
