"""CLI package for RETRO-Ollama."""

from src.cli.base import (
    console,
    print_banner,
    print_status,
    print_error,
    print_success,
    print_warning,
    print_info,
)
from src.cli.handlers import (
    list_models_cli,
    check_ollama_connection,
    select_model_cli,
    extract_ip_or_domain,
    extract_ports,
    extract_scan_args,
)

__all__ = [
    "console",
    "print_banner",
    "print_status",
    "print_error",
    "print_success",
    "print_warning",
    "print_info",
    "list_models_cli",
    "check_ollama_connection",
    "select_model_cli",
    "extract_ip_or_domain",
    "extract_ports",
    "extract_scan_args",
]
