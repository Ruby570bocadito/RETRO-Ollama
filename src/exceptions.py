"""Global error handling for RETRO-Ollama."""

import functools
import logging
import sys
import traceback
from typing import Any, Callable, Optional, TypeVar, Union

from rich.console import Console
from rich.panel import Panel
from rich.pretty import pprint

from src.logging_config import get_logger

logger = get_logger("ptai.errors")
console = Console()

T = TypeVar("T")


class PTAIException(Exception):
    """Base exception for RETRO-Ollama."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ValidationError(PTAIException):
    """Validation error."""
    pass


class ScanError(PTAIException):
    """Scan execution error."""
    pass


class ToolNotFoundError(PTAIException):
    """Tool not found error."""
    pass


class ConfigurationError(PTAIException):
    """Configuration error."""
    pass


class APIError(PTAIException):
    """API error."""
    pass


def format_exception(exc: Exception) -> str:
    """Format exception for display."""
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def print_error_panel(
    title: str,
    message: str,
    details: Optional[str] = None,
) -> None:
    """Print error panel with rich formatting."""
    content = f"[bold red]{message}[/bold red]"
    if details:
        content += f"\n\n[dim]{details}[/dim]"

    console.print(
        Panel(
            content,
            title=f"[bold red]{title}[/bold red]",
            border_style="red",
            expand=False,
        )
    )


def handle_exception(
    exc: Exception,
    context: Optional[str] = None,
    show_traceback: bool = False,
) -> None:
    """Handle and display exception."""
    error_type = type(exc).__name__
    error_message = str(exc)

    if context:
        logger.error(f"{context}: {error_type}: {error_message}")
    else:
        logger.error(f"{error_type}: {error_message}")

    if show_traceback or logger.level == logging.DEBUG:
        print_error_panel(
            f"Error: {error_type}",
            error_message,
            format_exception(exc) if show_traceback else None,
        )
    else:
        print_error_panel(
            f"Error: {error_type}",
            error_message,
            "Use --debug for full traceback",
        )


def exception_handler(
    func: Callable[..., T]
) -> Callable[..., Union[T, None]]:
    """Decorator for handling exceptions in functions."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Optional[T]:
        try:
            return func(*args, **kwargs)
        except PTAIException as e:
            handle_exception(e, context=func.__name__)
            return None
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
            sys.exit(130)
        except Exception as e:
            handle_exception(e, context=func.__name__, show_traceback=True)
            return None

    return wrapper


def async_exception_handler(
    func: Callable[..., Any]
) -> Callable[..., Any]:
    """Decorator for handling exceptions in async functions."""

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await func(*args, **kwargs)
        except PTAIException as e:
            handle_exception(e, context=func.__name__)
            return None
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
            sys.exit(130)
        except Exception as e:
            handle_exception(e, context=func.__name__, show_traceback=True)
            return None

    return wrapper


def install_global_exception_handler() -> None:
    """Install global exception handler."""

    def global_exception_handler(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return

        logger.critical(
            f"Unhandled exception: {exc_type.__name__}: {exc_value}",
            exc_info=(exc_type, exc_value, exc_traceback),
        )

        print_error_panel(
            "Unhandled Error",
            f"{exc_type.__name__}: {exc_value}",
            format_exception(exc_value),
        )

    sys.excepthook = global_exception_handler
