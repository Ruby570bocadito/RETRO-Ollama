"""Internationalization (i18n) for RETRO-Ollama."""

import gettext
import locale
import os
from pathlib import Path
from typing import Dict, Optional

from src.config.settings import BASE_DIR

TRANSLATIONS_DIR = BASE_DIR / "locales"

DEFAULT_LOCALE = "en"

TRANSLATIONS: Dict[str, gettext.GNUTranslations] = {}


def get_available_locales() -> list[str]:
    """Get list of available locales."""
    if not TRANSLATIONS_DIR.exists():
        return [DEFAULT_LOCALE]
    
    locales = []
    for item in TRANSLATIONS_DIR.iterdir():
        if item.is_dir() and (item / "LC_MESSAGES").exists():
            locales.append(item.name)
    
    return locales if locales else [DEFAULT_LOCALE]


def load_translations(locale_name: str) -> Optional[gettext.GNUTranslations]:
    """Load translations for a locale."""
    try:
        trans = gettext.translation(
            "messages",
            localedir=str(TRANSLATIONS_DIR),
            languages=[locale_name],
        )
        return trans
    except FileNotFoundError:
        return None


def init_i18n(locale_name: Optional[str] = None) -> str:
    """Initialize internationalization."""
    if locale_name is None:
        locale_name = os.getenv("LANG", "").split(".")[0]
    
    if not locale_name:
        try:
            locale_name = locale.getdefaultlocale()[0]
        except Exception:
            locale_name = DEFAULT_LOCALE
    
    if not locale_name:
        locale_name = DEFAULT_LOCALE
    
    lang_code = locale_name.split("_")[0]
    
    trans = load_translations(locale_name) or load_translations(lang_code)
    
    if trans is None:
        trans = load_translations(DEFAULT_LOCALE)
    
    if trans:
        TRANSLATIONS[locale_name] = trans
        trans.install()
    
    return locale_name


def t(key: str, **kwargs: str) -> str:
    """Translate a key."""
    try:
        trans = gettext.gettext
    except Exception:
        trans = lambda x: x
    
    result = trans(key)
    
    if kwargs:
        try:
            result = result.format(**kwargs)
        except Exception:
            pass
    
    return result


def n(singular: str, plural: str, n: int) -> str:
    """Translate with pluralization."""
    try:
        trans = gettext.ngettext
    except Exception:
        return singular if n == 1 else plural
    
    return trans(singular, plural, n)


current_locale = init_i18n()


MESSAGES = {
    "en": {
        "app_title": "RETRO-Ollama",
        "app_subtitle": "Pentesting AI Tool",
        "welcome": "Welcome to RETRO-Ollama",
        "select_backend": "Select backend",
        "select_model": "Select model",
        "connecting": "Connecting to {backend}...",
        "connected": "Connected to {backend}",
        "connection_failed": "Failed to connect to {backend}",
        "scan_started": "Scan started on {target}",
        "scan_completed": "Scan completed: {status}",
        "scan_failed": "Scan failed: {error}",
        "mode_changed": "Mode changed to {mode}",
        "current_mode": "Current mode: {mode}",
        "api_key_missing": "API key missing: {service}",
        "target_invalid": "Invalid target: {target}",
        "command_not_found": "Command not found: {command}",
        "help": "Help",
        "exit": "Exit",
        "error": "Error",
        "success": "Success",
        "warning": "Warning",
        "info": "Info",
    },
    "es": {
        "app_title": "RETRO-Ollama",
        "app_subtitle": "Herramienta de Pentesting IA",
        "welcome": "Bienvenido a RETRO-Ollama",
        "select_backend": "Seleccionar backend",
        "select_model": "Seleccionar modelo",
        "connecting": "Conectando a {backend}...",
        "connected": "Conectado a {backend}",
        "connection_failed": "Error al conectar a {backend}",
        "scan_started": "Escaneo iniciado en {target}",
        "scan_completed": "Escaneo completado: {status}",
        "scan_failed": "Escaneo fallido: {error}",
        "mode_changed": "Modo cambiado a {mode}",
        "current_mode": "Modo actual: {mode}",
        "api_key_missing": "Falta API key: {service}",
        "target_invalid": "Target inválido: {target}",
        "command_not_found": "Comando no encontrado: {command}",
        "help": "Ayuda",
        "exit": "Salir",
        "error": "Error",
        "success": "Éxito",
        "warning": "Advertencia",
        "info": "Info",
    },
    "pt": {
        "app_title": "RETRO-Ollama",
        "app_subtitle": "Ferramenta de Pentesting IA",
        "welcome": "Bem-vindo ao RETRO-Ollama",
        "select_backend": "Selecionar backend",
        "select_model": "Selecionar modelo",
        "connecting": "Conectando a {backend}...",
        "connected": "Conectado a {backend}",
        "connection_failed": "Falha ao conectar a {backend}",
        "scan_started": "Varredura iniciada em {target}",
        "scan_completed": "Varredura concluída: {status}",
        "scan_failed": "Varredura falhou: {error}",
        "mode_changed": "Modo alterado para {mode}",
        "current_mode": "Modo atual: {mode}",
        "api_key_missing": "API key ausente: {service}",
        "target_invalid": "Alvo inválido: {target}",
        "command_not_found": "Comando não encontrado: {command}",
        "help": "Ajuda",
        "exit": "Sair",
        "error": "Erro",
        "success": "Sucesso",
        "warning": "Aviso",
        "info": "Info",
    },
}


def get_message(key: str, locale_name: Optional[str] = None, **kwargs: str) -> str:
    """Get a translated message."""
    locale_name = locale_name or current_locale
    
    lang_code = locale_name.split("_")[0]
    
    messages = MESSAGES.get(locale_name) or MESSAGES.get(lang_code) or MESSAGES[DEFAULT_LOCALE]
    
    result = messages.get(key, key)
    
    if kwargs:
        try:
            result = result.format(**kwargs)
        except Exception:
            pass
    
    return result


__all__ = [
    "init_i18n",
    "t",
    "n",
    "get_message",
    "get_available_locales",
    "current_locale",
    "MESSAGES",
]
