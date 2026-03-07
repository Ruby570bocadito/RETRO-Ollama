import asyncio
import subprocess
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor
import threading

executor = ThreadPoolExecutor(max_workers=4)

def run_command_sync(command: str, timeout: int = 300) -> Dict:
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "output": "",
            "error": "Command timed out",
            "returncode": -1
        }
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "error": str(e),
            "returncode": -1
        }

async def run_command_async(command: str, timeout: int = 300) -> Dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, run_command_sync, command, timeout)

async def quick_scan_async(target: str) -> Dict:
    return await run_command_async(f"nmap -sV -sC -F {target}")

async def vuln_scan_async(target: str) -> Dict:
    return await run_command_async(f"nmap --script vuln -sV {target}")

async def full_scan_async(target: str) -> Dict:
    return await run_command_async(f"nmap -sV -sC -A -p- {target}")

async def web_scan_async(target: str) -> Dict:
    nikto = await run_command_async(f"nikto -h {target}")
    whatweb = await run_command_async(f"whatweb -a 3 {target}")
    return {
        "nikto": nikto,
        "whatweb": whatweb
    }

async def dir_scan_async(target: str, wordlist: str = None) -> Dict:
    if wordlist:
        return await run_command_async(f"gobuster dir -u {target} -w {wordlist}")
    return await run_command_async(f"gobuster dir -u {target}")

async def os_detect_async(target: str) -> Dict:
    return await run_command_async(f"nmap -O {target}")

async def dns_enum_async(target: str) -> Dict:
    return await run_command_async(f"dnsenum {target}")

async def subdomain_enum_async(target: str) -> Dict:
    return await run_command_async(f"sublist3r -d {target}")

async def autopwn_async(target: str) -> Dict:
    scan, vuln, web = await asyncio.gather(
        quick_scan_async(target),
        vuln_scan_async(target),
        web_scan_async(target)
    )
    
    return {
        "quick_scan": scan,
        "vuln_scan": vuln,
        "web_scan": web,
        "all_results": f"Nmap:\n{scan.get('output', '')}\n\nVuln:\n{vuln.get('output', '')}"
    }

async def fullpentest_async(target: str) -> Dict:
    results = await asyncio.gather(
        quick_scan_async(target),
        full_scan_async(target),
        os_detect_async(target),
        vuln_scan_async(target),
        web_scan_async(target),
        dir_scan_async(target),
        dns_enum_async(target),
        subdomain_enum_async(target),
        return_exceptions=True
    )
    
    names = ["quick", "full", "os", "vuln", "web", "dir", "dns", "subdomain"]
    result_dict = {}
    for name, res in zip(names, results):
        if isinstance(res, Exception):
            result_dict[name] = {"success": False, "error": str(res)}
        else:
            result_dict[name] = res
    
    return result_dict

def run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)
