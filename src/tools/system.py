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
