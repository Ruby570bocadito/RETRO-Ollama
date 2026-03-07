import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import shutil

BASE_DIR = Path(__file__).parent.parent.parent
SESSIONS_DIR = BASE_DIR / "sessions"

SESSIONS_DIR.mkdir(exist_ok=True)

def create_session(name: str = None) -> str:
    if not name:
        name = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    session_path = SESSIONS_DIR / name
    session_path.mkdir(exist_ok=True)
    
    session_data = {
        "name": name,
        "created": datetime.now().isoformat(),
        "targets": [],
        "history": [],
        "results": {},
        "files": []
    }
    
    save_session_data(name, session_data)
    return name

def save_session_data(name: str, data: Dict):
    session_path = SESSIONS_DIR / name / "session.json"
    with open(session_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def load_session(name: str) -> Optional[Dict]:
    session_path = SESSIONS_DIR / name / "session.json"
    if session_path.exists():
        with open(session_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

def list_sessions() -> List[Dict]:
    sessions = []
    if SESSIONS_DIR.exists():
        for s in SESSIONS_DIR.iterdir():
            if s.is_dir():
                data = load_session(s.name)
                if data:
                    sessions.append({
                        "name": data.get("name"),
                        "created": data.get("created"),
                        "targets": data.get("targets", []),
                        "file_count": len(list(s.glob("*"))) - 1
                    })
    return sorted(sessions, key=lambda x: x.get("created", ""), reverse=True)

def add_target_to_session(session_name: str, target: str, tool: str):
    data = load_session(session_name)
    if data:
        if target not in data["targets"]:
            data["targets"].append(target)
        
        target_dir = SESSIONS_DIR / session_name / "targets" / target
        target_dir.mkdir(parents=True, exist_ok=True)
        
        save_session_data(session_name, data)

def save_result_to_session(session_name: str, target: str, result_name: str, content: str):
    data = load_session(session_name)
    if data:
        target_dir = SESSIONS_DIR / session_name / "targets" / target
        target_dir.mkdir(parents=True, exist_ok=True)
        
        result_file = target_dir / f"{result_name}.txt"
        with open(result_file, "w", encoding="utf-8") as f:
            f.write(content)
        
        if target not in data["results"]:
            data["results"][target] = []
        if result_name not in data["results"][target]:
            data["results"][target].append(result_name)
        
        save_session_data(session_name, data)

def get_session_results(session_name: str, target: str = None) -> Dict:
    data = load_session(session_name)
    if not data:
        return {}
    
    results = {}
    if target:
        target_dir = SESSIONS_DIR / session_name / "targets" / target
        if target_dir.exists():
            for f in target_dir.glob("*.txt"):
                results[f.stem] = f.read_text(encoding="utf-8")
    else:
        for target in data.get("targets", []):
            target_dir = SESSIONS_DIR / session_name / "targets" / target
            if target_dir.exists():
                results[target] = {}
                for f in target_dir.glob("*.txt"):
                    results[target][f.stem] = f.read_text(encoding="utf-8")
    
    return results

def add_chat_to_session(session_name: str, role: str, content: str):
    data = load_session(session_name)
    if data:
        data["history"].append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
        save_session_data(session_name, data)

def delete_session(name: str) -> bool:
    session_path = SESSIONS_DIR / name
    if session_path.exists():
        shutil.rmtree(session_path)
        return True
    return False

def export_session(session_name: str) -> Optional[str]:
    data = load_session(session_name)
    if data:
        export_path = SESSIONS_DIR / session_name / "export.json"
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return str(export_path)
    return None
