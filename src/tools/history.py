import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

BASE_DIR = Path(__file__).parent.parent.parent
HISTORY_FILE = BASE_DIR / "history.json"


def load_history() -> List[Dict]:
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return []
    return []


def save_history(messages: List[Dict]):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(messages[-100:], f, ensure_ascii=False, indent=2)
    except:
        pass


def add_message(role: str, content: str):
    messages = load_history()
    messages.append({
        "role": role,
        "content": content,
        "timestamp": datetime.now().isoformat()
    })
    save_history(messages)


def clear_history():
    if HISTORY_FILE.exists():
        HISTORY_FILE.unlink()


def get_history_count() -> int:
    return len(load_history())


def search_history(query: str) -> List[Dict]:
    messages = load_history()
    results = []
    for msg in messages:
        if query.lower() in msg.get("content", "").lower():
            results.append(msg)
    return results
