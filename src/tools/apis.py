import requests
import logging
from typing import Dict, Optional, List

from src.config.settings import (
    SHODAN_API_KEY,
    VIRUSTOTAL_API_KEY,
    HUNTER_API_KEY,
)
from src.tools.rate_limit import (
    exponential_backoff,
    shodan_limiter,
    virustotal_limiter,
    hunter_limiter,
    censys_limiter,
    securitytrails_limiter,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@exponential_backoff(max_retries=3)
def shodan_scan(ip: str) -> Dict:
    if not SHODAN_API_KEY:
        return {"success": False, "error": "SHODAN_API_KEY no configurada", "output": ""}
    
    if not shodan_limiter.is_allowed(ip):
        wait = shodan_limiter.wait_time(ip)
        return {"success": False, "error": f"Rate limit. Wait {wait:.1f}s", "output": ""}
    
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
        logger.error(f"Shodan scan error: {e}")
        return {"success": False, "error": str(e), "output": ""}


@exponential_backoff(max_retries=3)
def virustotal_scan(domain: str) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {"success": False, "error": "VIRUSTOTAL_API_KEY no configurada", "output": ""}
    
    if not virustotal_limiter.is_allowed(domain):
        wait = virustotal_limiter.wait_time(domain)
        return {"success": False, "error": f"Rate limit. Wait {wait:.1f}s", "output": ""}
    
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
        logger.error(f"VirusTotal scan error: {e}")
        return {"success": False, "error": str(e), "output": ""}


@exponential_backoff(max_retries=3)
def hunter_lookup(domain: str) -> Dict:
    if not HUNTER_API_KEY:
        return {"success": False, "error": "HUNTER_API_KEY no configurada", "output": ""}
    
    if not hunter_limiter.is_allowed(domain):
        wait = hunter_limiter.wait_time(domain)
        return {"success": False, "error": f"Rate limit. Wait {wait:.1f}s", "output": ""}
    
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
        logger.error(f"Hunter lookup error: {e}")
        return {"success": False, "error": str(e), "output": ""}


@exponential_backoff(max_retries=3)
def censys_lookup(ip: str) -> Dict:
    from src.config.settings import CENSYS_API_KEY
    
    if not CENSYS_API_KEY:
        return {"success": False, "error": "CENSYS_API_KEY no configurada", "output": ""}
    
    if not censys_limiter.is_allowed(ip):
        wait = censys_limiter.wait_time(ip)
        return {"success": False, "error": f"Rate limit. Wait {wait:.1f}s", "output": ""}
    
    try:
        url = f"https://search.censys.io/api/v1/hosts/{ip}"
        headers = {"Authorization": f"Basic {CENSYS_API_KEY}"}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            output = f"""
=== CENSYS - {ip} ===
Protocols: {data.get('protocols', [])}
OS: {data.get('operating_system', {}).get('pretty_name', 'N/A')}
Services: {len(data.get('services', []))} services found
            """
            return {"success": True, "output": output, "error": ""}
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        logger.error(f"Censys lookup error: {e}")
        return {"success": False, "error": str(e), "output": ""}


@exponential_backoff(max_retries=3)
def securitytrails_lookup(domain: str) -> Dict:
    from src.config.settings import SECURITYTRAILS_API_KEY
    
    if not SECURITYTRAILS_API_KEY:
        return {"success": False, "error": "SECURITYTRAILS_API_KEY no configurada", "output": ""}
    
    if not securitytrails_limiter.is_allowed(domain):
        wait = securitytrails_limiter.wait_time(domain)
        return {"success": False, "error": f"Rate limit. Wait {wait:.1f}s", "output": ""}
    
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/overview"
        headers = {"apikey": SECURITYTRAILS_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            output = f"""
=== SECURITYTRAILS - {domain} ===
Alexa Rank: {data.get('alexa_rank', 'N/A')}
DNS: {data.get('dns', [])}
Subdomains: {data.get('subdomains', [])[:10]}
            """
            return {"success": True, "output": output, "error": ""}
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        logger.error(f"SecurityTrails lookup error: {e}")
        return {"success": False, "error": str(e), "output": ""}


@exponential_backoff(max_retries=3)
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
        logger.error(f"CRT.sh lookup error: {e}")
        return {"success": False, "error": str(e), "output": ""}


@exponential_backoff(max_retries=3)
def whois_lookup(domain: str) -> Dict:
    try:
        url = f"https://whois.freeaiapi.xyz/api?domain={domain}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return {"success": True, "output": r.text[:2000], "error": ""}
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        logger.error(f"Whois lookup error: {e}")
        return {"success": False, "error": str(e), "output": ""}
