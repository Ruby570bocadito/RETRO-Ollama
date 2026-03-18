import requests
import logging
import hashlib
import time
import json
from typing import Dict, Optional, List, Any
from pathlib import Path

from src.config import get_config
from src.tools.rate_limit import (
    exponential_backoff,
    shodan_limiter,
    virustotal_limiter,
    hunter_limiter,
    censys_limiter,
    securitytrails_limiter,
)
from src.tools.security import sanitize_target

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simple file-based cache
CACHE_DIR = Path(__file__).parent.parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)
CACHE_TTL = 3600  # 1 hour cache TTL

def _get_cache_key(prefix: str, identifier: str) -> str:
    """Generate a cache key from prefix and identifier"""
    return f"{prefix}_{hashlib.md5(identifier.encode()).hexdigest()}"

def _get_cached_result(cache_key: str) -> Optional[Dict]:
    """Get cached result if it exists and is not expired"""
    cache_file = CACHE_DIR / f"{cache_key}.json"
    if not cache_file.exists():
        return None
    
    try:
        with open(cache_file, 'r') as f:
            cached = json.load(f)
        
        # Check if cache is expired
        if time.time() - cached.get('timestamp', 0) > CACHE_TTL:
            # Remove expired cache
            cache_file.unlink(missing_ok=True)
            return None
            
        return cached.get('data')
    except Exception:
        # If there's any error reading cache, return None
        return None

def _save_to_cache(cache_key: str, data: Dict) -> None:
    """Save data to cache with timestamp"""
    cache_file = CACHE_DIR / f"{cache_key}.json"
    try:
        with open(cache_file, 'w') as f:
            json.dump({
                'timestamp': time.time(),
                'data': data
            }, f)
    except Exception as e:
        logger.warning(f"Failed to save to cache: {e}")


@exponential_backoff(max_retries=3)
def shodan_scan(ip: str) -> Dict:
    config = get_config()
    if not config.api_keys.shodan:
        return {"success": False, "error": "SHODAN_API_KEY no configurada", "output": ""}
    
    # Sanitize input
    sanitized_ip = sanitize_target(ip)
    if not sanitized_ip:
        return {"success": False, "error": "Invalid IP address", "output": ""}
    
    # Check cache first
    cache_key = _get_cache_key("shodan", sanitized_ip)
    cached_result = _get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    if not shodan_limiter.is_allowed(sanitized_ip):
        wait = shodan_limiter.wait_time(sanitized_ip)
        return {"success": False, "error": f"Rate limit. Wait {wait:.1f}s", "output": ""}
    
    try:
        url = f"https://api.shodan.io/shodan/host/{sanitized_ip}"
        params = {"key": config.api_keys.shodan}
        r = requests.get(url, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            output = f"""
=== SHODAN - {sanitized_ip} ===
ISP: {data.get('isp', 'N/A')}
OS: {data.get('os', 'N/A')}
Ports: {data.get('ports', [])}
Hostnames: {data.get('hostnames', [])}
Vulns: {data.get('vulns', [])}
            """
            result = {"success": True, "output": output, "error": ""}
            # Save to cache
            _save_to_cache(cache_key, result)
            return result
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        logger.error(f"Shodan scan error: {e}")
        return {"success": False, "error": str(e), "output": ""}


@exponential_backoff(max_retries=3)
def virustotal_scan(domain: str) -> Dict:
    config = get_config()
    if not config.api_keys.virustotal:
        return {"success": False, "error": "VIRUSTOTAL_API_KEY no configurada", "output": ""}
    
    # Sanitize input
    sanitized_domain = sanitize_target(domain)
    if not sanitized_domain:
        return {"success": False, "error": "Invalid domain", "output": ""}
    
    # Check cache first
    cache_key = _get_cache_key("virustotal", sanitized_domain)
    cached_result = _get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    if not virustotal_limiter.is_allowed(sanitized_domain):
        wait = virustotal_limiter.wait_time(sanitized_domain)
        return {"success": False, "error": f"Rate limit. Wait {wait:.1f}s", "output": ""}
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{sanitized_domain}"
        headers = {"x-apikey": config.api_keys.virustotal}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            output = f"""
=== VIRUSTOTAL - {sanitized_domain} ===
Malicious: {stats.get('malicious', 0)}
Suspicious: {stats.get('suspicious', 0)}
Harmless: {stats.get('undetected', 0)}
            """
            result = {"success": True, "output": output, "error": ""}
            # Save to cache
            _save_to_cache(cache_key, result)
            return result
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        logger.error(f"VirusTotal scan error: {e}")
        return {"success": False, "error": str(e), "output": ""}


@exponential_backoff(max_retries=3)
def hunter_lookup(domain: str) -> Dict:
    config = get_config()
    if not config.api_keys.hunter:
        return {"success": False, "error": "HUNTER_API_KEY no configurada", "output": ""}
    
    # Sanitize input
    sanitized_domain = sanitize_target(domain)
    if not sanitized_domain:
        return {"success": False, "error": "Invalid domain", "output": ""}
    
    # Check cache first
    cache_key = _get_cache_key("hunter", sanitized_domain)
    cached_result = _get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    if not hunter_limiter.is_allowed(sanitized_domain):
        wait = hunter_limiter.wait_time(sanitized_domain)
        return {"success": False, "error": f"Rate limit. Wait {wait:.1f}s", "output": ""}
    
    try:
        url = f"https://api.hunter.io/v2/domain-search"
        params = {"domain": sanitized_domain, "api_key": config.api_keys.hunter}
        r = requests.get(url, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            emails = data.get("data", {}).get("emails", [])[:5]
            output = f"=== HUNTER - {sanitized_domain} ===\n"
            for e in emails:
                output += f"{e.get('email')} - {e.get('type')}\n"
            result = {"success": True, "output": output, "error": ""}
            # Save to cache
            _save_to_cache(cache_key, result)
            return result
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        logger.error(f"Hunter lookup error: {e}")
        return {"success": False, "error": str(e), "output": ""}


@exponential_backoff(max_retries=3)
def censys_lookup(ip: str) -> Dict:
    config = get_config()
    if not config.api_keys.censys:
        return {"success": False, "error": "CENSYS_API_KEY no configurada", "output": ""}
    
    # Sanitize input
    sanitized_ip = sanitize_target(ip)
    if not sanitized_ip:
        return {"success": False, "error": "Invalid IP address", "output": ""}
    
    # Check cache first
    cache_key = _get_cache_key("censys", sanitized_ip)
    cached_result = _get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    if not censys_limiter.is_allowed(sanitized_ip):
        wait = censys_limiter.wait_time(sanitized_ip)
        return {"success": False, "error": f"Rate limit. Wait {wait:.1f}s", "output": ""}
    
    try:
        url = f"https://search.censys.io/api/v1/hosts/{sanitized_ip}"
        headers = {"Authorization": f"Basic {config.api_keys.censys}"}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            output = f"""
=== CENSYS - {sanitized_ip} ===
Protocols: {data.get('protocols', [])}
OS: {data.get('operating_system', {}).get('pretty_name', 'N/A')}
Services: {len(data.get('services', []))} services found
            """
            result = {"success": True, "output": output, "error": ""}
            # Save to cache
            _save_to_cache(cache_key, result)
            return result
        return {"success": False, "error": f"Error: {r.status_code}", "output": ""}
    except Exception as e:
        logger.error(f"Censys lookup error: {e}")
        return {"success": False, "error": str(e), "output": ""}


@exponential_backoff(max_retries=3)
def securitytrails_lookup(domain: str) -> Dict:
    config = get_config()
    if not config.api_keys.securitytrails:
        return {"success": False, "error": "SECURITYTRAILS_API_KEY no configurada", "output": ""}
    
    # Sanitize input
    sanitized_domain = sanitize_target(domain)
    if not sanitized_domain:
        return {"success": False, "error": "Invalid domain", "output": ""}
    
    # Check cache first
    cache_key = _get_cache_key("securitytrails", sanitized_domain)
    cached_result = _get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result
    
    if not securitytrails_limiter.is_allowed(sanitized_domain):
        wait = securitytrails_limiter.wait_time(sanitized_domain)
        return {"success": False, "error": f"Rate limit. Wait {wait:.1f}s", "output": ""}
    
    try:
        url = f"https://api.securitytrails.com/v1/domain/{sanitized_domain}/overview"
        headers = {"apikey": config.api_keys.securitytrails}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            output = f"""
=== SECURITYTRAILS - {sanitized_domain} ===
Alexa Rank: {data.get('alexa_rank', 'N/A')}
DNS: {data.get('dns', [])}
Subdomains: {data.get('subdomains', [])[:10]}
            """
            result = {"success": True, "output": output, "error": ""}
            # Save to cache
            _save_to_cache(cache_key, result)
            return result
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
