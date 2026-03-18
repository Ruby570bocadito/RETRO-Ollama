"""CLI command handlers for RETRO-Ollama."""

import re
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich import box

from src.cli.base import console, print_error, print_success

console = Console()


def list_models_cli(ollama) -> list:
    """List available models."""
    models = ollama.list_models()
    if not models:
        print_error("No models available")
        return []
    
    table = Table(title="", box=box.SIMPLE, show_header=False)
    table.add_column("ID", style="#808080", justify="center", width=4)
    table.add_column("Model", style="#A0A0A0")
    table.add_column("Size", style="#606060", justify="right")
    
    for i, m in enumerate(models, 1):
        size_gb = m.get("size", 0) / (1024**3)
        table.add_row(f"[{i}]", m.get("name", "Unknown"), f"{size_gb:.2f} GB")
    
    console.print(table)
    return models


def check_ollama_connection(ollama) -> bool:
    """Check Ollama connection."""
    if not ollama.check_connection():
        print_error(f"Cannot connect to {ollama.backend_name}")
        return False
    print_success(f"Connected to {ollama.backend_name}")
    return True


def select_model_cli(ollama) -> str:
    """Interactive model selection."""
    console.print("""
  [1]  Ollama    (localhost:11434)
  [2]  LM Studio (localhost:1234)
  [3]  Llama.cpp (localhost:8080)
""")
    
    backend_choice = console.input(">> Choose (1-3): ")
    
    backend_map = {
        "1": "ollama",
        "2": "lmstudio", 
        "3": "llamacpp",
    }
    
    backend = backend_map.get(backend_choice, "ollama")
    
    if not ollama.check_connection():
        print_error(f"Cannot connect to {backend}")
        return "llama3.2"
    
    print_success(f"Connected to {backend}")
    
    models = ollama.list_models()
    if not models:
        print_error("No models available")
        return "llama3.2"
    
    console.print(f"\nAvailable Models ({len(models)}):")
    for i, m in enumerate(models, 1):
        name = m.get("name", "Unknown")
        size = m.get("size", 0) / (1024**3)
        console.print(f"  [{i}] {name} ({size:.2f} GB)")
    
    try:
        choice = int(console.input("\nSelect model: ")) - 1
        if 0 <= choice < len(models):
            return models[choice].get("name", "llama3.2")
    except ValueError:
        pass
    
    return models[0].get("name", "llama3.2")


def extract_ip_or_domain(text: str) -> Optional[str]:
    """Extract IP or domain from text."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    ip_match = re.search(ip_pattern, text)
    if ip_match:
        return ip_match.group()
    
    domain_match = re.search(domain_pattern, text)
    if domain_match:
        return domain_match.group()
    
    return None


def extract_ports(text: str) -> Optional[str]:
    """Extract ports from text."""
    port_pattern = r'-p\s*([\d,]+)|puertos?\s*([\d,]+)|port\s*([\d,]+)'
    match = re.search(port_pattern, text, re.IGNORECASE)
    if match:
        for g in match.groups():
            if g:
                return g
    return None


def extract_scan_args(text: str) -> dict:
    """Extract scan arguments from text."""
    args = {
        "target": extract_ip_or_domain(text),
        "ports": extract_ports(text),
    }
    
    stealth = any(w in text.lower() for w in ["stealth", "sigiloso", "evasion"])
    if stealth:
        args["stealth"] = True
    
    full = any(w in text.lower() for w in ["full", "completo", "exhaustivo"])
    if full:
        args["full"] = True
    
    return args
