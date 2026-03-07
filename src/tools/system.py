import os
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

BASE_DIR = Path(__file__).parent.parent
OUTPUT_DIR = BASE_DIR / "output"
SCRIPTS_DIR = OUTPUT_DIR / "scripts"
TOOLS_DIR = OUTPUT_DIR / "tools"
PAYLOADS_DIR = OUTPUT_DIR / "payloads"
EXPLOITS_DIR = OUTPUT_DIR / "exploits"

os.makedirs(SCRIPTS_DIR, exist_ok=True)
os.makedirs(TOOLS_DIR, exist_ok=True)
os.makedirs(PAYLOADS_DIR, exist_ok=True)
os.makedirs(EXPLOITS_DIR, exist_ok=True)


def save_code(content: str, filename: str, category: str = "scripts") -> Path:
    categories = {
        "script": SCRIPTS_DIR,
        "scripts": SCRIPTS_DIR,
        "tool": TOOLS_DIR,
        "tools": TOOLS_DIR,
        "payload": PAYLOADS_DIR,
        "payloads": PAYLOADS_DIR,
        "exploit": EXPLOITS_DIR,
        "exploits": EXPLOITS_DIR
    }
    
    target_dir = categories.get(category.lower(), SCRIPTS_DIR)
    
    if not filename.endswith((".py", ".sh", ".ps1", ".rb", ".js", ".txt", ".md")):
        ext = ".py" if "python" in content.lower() or "def " in content else ".sh"
        filename += ext
    
    filepath = target_dir / filename
    counter = 1
    while filepath.exists():
        stem = filepath.stem
        suffix = filepath.suffix
        filepath = target_dir / f"{stem}_{counter}{suffix}"
        counter += 1
    
    filepath.write_text(content, encoding="utf-8")
    make_executable(filepath)
    return filepath


def make_executable(filepath: Path):
    if os.name != 'nt':
        filepath.chmod(0o755)


def read_file(filepath: str) -> Optional[str]:
    try:
        path = Path(filepath)
        if path.exists():
            return path.read_text(encoding="utf-8")
    except:
        pass
    return None


def edit_file(filepath: str, new_content: str) -> bool:
    try:
        path = Path(filepath)
        if path.exists():
            path.write_text(new_content, encoding="utf-8")
            return True
    except:
        pass
    return False


def list_files(category: str = "all") -> Dict[str, List[Dict]]:
    result = {}
    
    if category in ["all", "scripts"]:
        result["scripts"] = list_files_in_dir(SCRIPTS_DIR)
    if category in ["all", "tools"]:
        result["tools"] = list_files_in_dir(TOOLS_DIR)
    if category in ["all", "payloads"]:
        result["payloads"] = list_files_in_dir(PAYLOADS_DIR)
    if category in ["all", "exploits"]:
        result["exploits"] = list_files_in_dir(EXPLOITS_DIR)
    
    return result


def list_files_in_dir(directory: Path) -> List[Dict]:
    files = []
    if directory.exists():
        for f in sorted(directory.iterdir()):
            if f.is_file():
                stat = f.stat()
                files.append({
                    "name": f.name,
                    "path": str(f),
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                })
    return files


def delete_file(filepath: str) -> bool:
    try:
        path = Path(filepath)
        if path.exists():
            path.unlink()
            return True
    except:
        pass
    return False


def execute_command(command: str, timeout: int = 60, cwd: Optional[str] = None) -> Dict:
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd
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


def run_script(filepath: str, args: str = "", timeout: int = 60) -> Dict:
    path = Path(filepath)
    if not path.exists():
        return {"success": False, "output": "", "error": "File not found", "returncode": -1}
    
    if path.suffix == ".py":
        cmd = f"python {filepath} {args}"
    elif path.suffix == ".sh":
        cmd = f"bash {filepath} {args}"
    elif path.suffix == ".ps1":
        cmd = f"powershell -ExecutionPolicy Bypass -File {filepath} {args}"
    else:
        cmd = f"{filepath} {args}"
    
    return execute_command(cmd, timeout)


def search_exploits(keyword: str) -> Dict:
    result = execute_command(f"searchsploit {keyword}", timeout=30)
    return result


def get_output_dir() -> str:
    return str(OUTPUT_DIR)


def ls_directory(path: str = ".") -> Dict:
    try:
        target = Path(path)
        if not target.exists():
            return {"success": False, "output": "", "error": f"Path not found: {path}"}
        
        items = []
        for item in sorted(target.iterdir()):
            stat = item.stat()
            item_type = "dir" if item.is_dir() else "file"
            items.append({
                "name": item.name,
                "type": item_type,
                "size": stat.st_size if item.is_file() else 0,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            })
        
        return {"success": True, "output": items, "error": ""}
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}


def get_processes() -> Dict:
    try:
        if os.name == 'nt':
            result = execute_command('tasklist /FO TABLE /NH', timeout=15)
        else:
            result = execute_command('ps aux --no-headers', timeout=15)
        
        if result["success"]:
            lines = result["output"].strip().split('\n')[:30]
            output = "[+] Procesos en ejecucion:\n\n"
            for line in lines:
                if line.strip():
                    output += f"  - {line.strip()}\n"
            return {"success": True, "output": output, "error": ""}
        return result
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}


def get_network_connections() -> Dict:
    try:
        if os.name == 'nt':
            result = execute_command('netstat -ano | findstr ESTABLISHED', timeout=15)
        else:
            result = execute_command('netstat -tun | grep ESTABLISHED', timeout=15)
        
        return {"success": result["success"], "output": result["output"][:2000], "error": result["error"]}
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}


def get_system_info() -> Dict:
    try:
        import platform
        info = {"os": os.name, "platform": platform.system()}
        
        if os.name == 'nt':
            result = execute_command('systeminfo /FO CSV /NH', timeout=20)
            if result["success"]:
                info["systeminfo"] = result["output"][:1500]
        else:
            result = execute_command('uname -a && df -h && free -m', timeout=15)
            if result["success"]:
                info["systeminfo"] = result["output"]
        
        return {"success": True, "output": info, "error": ""}
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}


def check_tool(tool_name: str) -> Dict:
    try:
        result = execute_command(f'where {tool_name}' if os.name == 'nt' else f'which {tool_name}', timeout=5)
        
        if result["success"] and result["output"].strip():
            return {"success": True, "output": f"{tool_name} found: {result['output'].strip()}", "error": ""}
        
        result = execute_command(f'{tool_name} --version', timeout=5)
        if result["success"]:
            return {"success": True, "output": f"{tool_name} installed: {result['output'][:200]}", "error": ""}
        
        return {"success": False, "output": "", "error": f"{tool_name} not found"}
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}


def get_services() -> Dict:
    try:
        if os.name == 'nt':
            result = execute_command('sc query state= all', timeout=20)
        else:
            result = execute_command('systemctl list-units --type=service --state=running', timeout=15)
        
        if result["success"]:
            lines = result["output"].strip().split('\n')[:30]
            output = "[+] Servicios en ejecucion:\n\n"
            for line in lines:
                if line.strip():
                    output += f"  - {line.strip()}\n"
            return {"success": True, "output": output, "error": ""}
        return result
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}


def get_disk_info() -> Dict:
    try:
        if os.name == 'nt':
            result = execute_command('powershell -Command "Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free | Format-Table -AutoSize"', timeout=15)
        else:
            result = execute_command('df -h', timeout=15)
        
        if result["success"]:
            return {"success": True, "output": f"[+] Disco:\n{result['output']}", "error": ""}
        return result
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}


def get_network_info() -> Dict:
    try:
        if os.name == 'nt':
            result = execute_command('ipconfig /all', timeout=15)
        else:
            result = execute_command('ip addr show', timeout=15)
        
        if result["success"]:
            return {"success": True, "output": f"[+] Red:\n{result['output'][:3000]}", "error": ""}
        return result
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}


def check_pentest_env() -> Dict:
    checks = []
    
    if os.name == 'nt':
        result = execute_command('where nmap', timeout=5)
        checks.append(("Nmap", result["success"]))
        
        result = execute_command('where python', timeout=5)
        checks.append(("Python", result["success"]))
        
        result = execute_command('where docker', timeout=5)
        checks.append(("Docker", result["success"]))
        
        result = execute_command('where git', timeout=5)
        checks.append(("Git", result["success"]))
        
        result = execute_command('where curl', timeout=5)
        checks.append(("Curl", result["success"]))
        
        result = execute_command('where wsl', timeout=5)
        checks.append(("WSL", result["success"]))
        
        result = execute_command('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"', timeout=10)
        os_info = result["output"].strip() if result["success"] else "Windows"
    else:
        for tool in ["nmap", "python3", "docker", "git", "curl"]:
            result = execute_command(f"which {tool}", timeout=5)
            checks.append((tool.capitalize(), result["success"]))
        
        result = execute_command("uname -a", timeout=5)
        os_info = result["output"].strip() if result["success"] else "Linux"
    
    output = f"[+] Entorno de Pentesting\n"
    output += f"  SO: {os_info}\n\n"
    output += "[+] Herramientas:\n"
    for name, installed in checks:
        status = "[+]" if installed else "[-]"
        output += f"  {status} {name}\n"
    
    return {"success": True, "output": output, "error": ""}


def get_wifi_networks() -> Dict:
    try:
        if os.name == 'nt':
            result = execute_command('netsh wlan show networks mode=bssid', timeout=15)
        else:
            result = execute_command('nmcli dev wifi', timeout=15)
        
        if result["success"]:
            return {"success": True, "output": f"[+] Redes WiFi:\n{result['output'][:2000]}", "error": ""}
        return result
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}


def run_wsl(command: str) -> Dict:
    try:
        result = execute_command(f'wsl {command}', timeout=60)
        return result
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}


def check_wsl_tools() -> Dict:
    tools = ["nmap", "nikto", "sqlmap", "hydra", "searchsploit", "gobuster", "msfconsole"]
    output = "[+] Herramientas en WSL:\n\n"
    
    for tool in tools:
        result = execute_command(f'wsl which {tool}', timeout=10)
        status = "[+]" if result["success"] and result["output"].strip() else "[-]"
        output += f"  {status} {tool}\n"
    
    return {"success": True, "output": output, "error": ""}
